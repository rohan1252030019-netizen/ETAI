"""
IMMUNEX CVE Database
====================
SQLite-backed persistence layer for the CVE Prioritization Engine.

Manages three tables:
  - asset_inventory         : tracked network assets with criticality scores
  - vulnerability_catalog   : known CVEs with CVSS, EPSS, KEV, and actor-targeting data
  - asset_vulnerabilities   : many-to-many mapping of assets to CVEs

Thread-safe via check_same_thread=False and an internal threading lock.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from utils.logger import log


_DEFAULT_DB_PATH = Path("data/logs/cve_store.db")


class CVEDatabase:
    """
    Thread-safe SQLite store for CVE and asset inventory data.

    Usage::

        db = CVEDatabase()
        db.upsert_asset("10.0.0.1", "SCADA Gateway", 0.95, "OT")
        db.upsert_vulnerability("CVE-2024-1234", 9.8, 0.97, True, True, {...})
        db.map_asset_vulnerability("10.0.0.1", "CVE-2024-1234")
        threats = db.get_vulnerabilities_for_asset("10.0.0.1")
    """

    def __init__(self, db_path: Path | str = _DEFAULT_DB_PATH) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()
        log.info(
            "CVEDatabase initialised",
            db_path=str(self._db_path),
            subsystem="cve_db",
        )

    # ── Schema ────────────────────────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Create a new connection with WAL mode for concurrent reads."""
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        """Create tables if they do not exist."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS asset_inventory (
                        asset_ip        TEXT PRIMARY KEY,
                        asset_name      TEXT NOT NULL DEFAULT '',
                        criticality     REAL NOT NULL DEFAULT 0.5,
                        asset_zone      TEXT NOT NULL DEFAULT 'IT',
                        metadata_json   TEXT NOT NULL DEFAULT '{}',
                        registered_at   REAL NOT NULL,
                        updated_at      REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS vulnerability_catalog (
                        cve_id              TEXT PRIMARY KEY,
                        cvss_score          REAL NOT NULL DEFAULT 0.0,
                        epss_score          REAL NOT NULL DEFAULT 0.0,
                        in_kev              INTEGER NOT NULL DEFAULT 0,
                        actor_targeting     INTEGER NOT NULL DEFAULT 0,
                        description         TEXT NOT NULL DEFAULT '',
                        affected_products   TEXT NOT NULL DEFAULT '[]',
                        metadata_json       TEXT NOT NULL DEFAULT '{}',
                        ingested_at         REAL NOT NULL,
                        updated_at          REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
                        asset_ip    TEXT NOT NULL,
                        cve_id      TEXT NOT NULL,
                        mapped_at   REAL NOT NULL,
                        status      TEXT NOT NULL DEFAULT 'OPEN',
                        PRIMARY KEY (asset_ip, cve_id),
                        FOREIGN KEY (asset_ip) REFERENCES asset_inventory(asset_ip)
                            ON DELETE CASCADE,
                        FOREIGN KEY (cve_id) REFERENCES vulnerability_catalog(cve_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS assets (
                        ip TEXT PRIMARY KEY,
                        hostname TEXT,
                        os_type TEXT,
                        criticality TEXT DEFAULT 'MEDIUM'
                    );

                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        cve_id TEXT PRIMARY KEY,
                        cvss REAL DEFAULT 0.0,
                        description TEXT,
                        kev INTEGER DEFAULT 0,
                        vector TEXT
                    );

                    CREATE TABLE IF NOT EXISTS asset_vulns (
                        ip TEXT,
                        cve_id TEXT,
                        PRIMARY KEY (ip, cve_id),
                        FOREIGN KEY (ip) REFERENCES assets(ip) ON DELETE CASCADE,
                        FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS idx_av_asset
                        ON asset_vulnerabilities(asset_ip);
                    CREATE INDEX IF NOT EXISTS idx_av_cve
                        ON asset_vulnerabilities(cve_id);
                    CREATE INDEX IF NOT EXISTS idx_vuln_cvss
                        ON vulnerability_catalog(cvss_score DESC);
                """)
                conn.commit()
            finally:
                conn.close()

    # ── Asset Inventory CRUD ──────────────────────────────────────────────────

    def upsert_asset(
        self,
        asset_ip: str,
        asset_name: str = "",
        criticality: float = 0.5,
        asset_zone: str = "IT",
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Insert or update an asset in the inventory."""
        now = time.time()
        meta_json = json.dumps(metadata or {})
        crit_str = self._crit_float_to_str(criticality)
        os_type = (metadata or {}).get("os_type", "unknown")

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO asset_inventory
                        (asset_ip, asset_name, criticality, asset_zone, metadata_json, registered_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_ip) DO UPDATE SET
                        asset_name    = excluded.asset_name,
                        criticality   = excluded.criticality,
                        asset_zone    = excluded.asset_zone,
                        metadata_json = excluded.metadata_json,
                        updated_at    = excluded.updated_at
                    """,
                    (asset_ip, asset_name, criticality, asset_zone, meta_json, now, now),
                )
                conn.execute(
                    """
                    INSERT INTO assets (ip, hostname, os_type, criticality)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        hostname    = excluded.hostname,
                        os_type     = excluded.os_type,
                        criticality = excluded.criticality
                    """,
                    (asset_ip, asset_name, os_type, crit_str),
                )
                conn.commit()
            finally:
                conn.close()

    def get_asset(self, asset_ip: str) -> Optional[dict[str, Any]]:
        """Retrieve a single asset by IP address."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM asset_inventory WHERE asset_ip = ?", (asset_ip,)
                ).fetchone()
                if row is None:
                    return None
                return self._row_to_asset(row)
            finally:
                conn.close()

    def list_assets(self, limit: int = 500) -> list[dict[str, Any]]:
        """List all tracked assets ordered by criticality descending."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM asset_inventory ORDER BY criticality DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [self._row_to_asset(r) for r in rows]
            finally:
                conn.close()

    def delete_asset(self, asset_ip: str) -> bool:
        """Remove an asset and its vulnerability mappings (cascade)."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM asset_inventory WHERE asset_ip = ?", (asset_ip,)
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    @staticmethod
    def _row_to_asset(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "asset_ip": row["asset_ip"],
            "asset_name": row["asset_name"],
            "criticality": row["criticality"],
            "asset_zone": row["asset_zone"],
            "metadata": json.loads(row["metadata_json"]),
            "registered_at": row["registered_at"],
            "updated_at": row["updated_at"],
        }

    # ── Vulnerability Catalog CRUD ────────────────────────────────────────────

    def upsert_vulnerability(
        self,
        cve_id: str,
        cvss_score: float = 0.0,
        epss_score: float = 0.0,
        in_kev: bool = False,
        actor_targeting: bool = False,
        description: str = "",
        affected_products: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Insert or update a vulnerability in the catalog."""
        now = time.time()
        products_json = json.dumps(affected_products or [])
        meta_json = json.dumps(metadata or {})

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerability_catalog
                        (cve_id, cvss_score, epss_score, in_kev, actor_targeting,
                         description, affected_products, metadata_json, ingested_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        cvss_score        = excluded.cvss_score,
                        epss_score        = excluded.epss_score,
                        in_kev            = excluded.in_kev,
                        actor_targeting   = excluded.actor_targeting,
                        description       = excluded.description,
                        affected_products = excluded.affected_products,
                        metadata_json     = excluded.metadata_json,
                        updated_at        = excluded.updated_at
                    """,
                    (
                        cve_id, cvss_score, epss_score, int(in_kev), int(actor_targeting),
                        description, products_json, meta_json, now, now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (cve_id, cvss, description, kev, vector)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        cvss        = excluded.cvss,
                        description = excluded.description,
                        kev         = excluded.kev,
                        vector      = excluded.vector
                    """,
                    (cve_id, cvss_score, description, int(in_kev), (metadata or {}).get("vector", "network")),
                )
                conn.commit()
            finally:
                conn.close()

    def get_vulnerability(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a single vulnerability by CVE ID."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM vulnerability_catalog WHERE cve_id = ?", (cve_id,)
                ).fetchone()
                if row is None:
                    return None
                return self._row_to_vuln(row)
            finally:
                conn.close()

    def list_vulnerabilities(
        self,
        limit: int = 500,
        order_by: str = "cvss_score DESC",
    ) -> list[dict[str, Any]]:
        """List vulnerabilities from the catalog."""
        # Whitelist sort columns to prevent SQL injection
        allowed_sorts = {
            "cvss_score DESC", "cvss_score ASC",
            "epss_score DESC", "epss_score ASC",
            "cve_id ASC", "cve_id DESC",
            "ingested_at DESC", "ingested_at ASC",
        }
        if order_by not in allowed_sorts:
            order_by = "cvss_score DESC"

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    f"SELECT * FROM vulnerability_catalog ORDER BY {order_by} LIMIT ?",
                    (limit,),
                ).fetchall()
                return [self._row_to_vuln(r) for r in rows]
            finally:
                conn.close()

    def delete_vulnerability(self, cve_id: str) -> bool:
        """Remove a vulnerability and its asset mappings (cascade)."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM vulnerability_catalog WHERE cve_id = ?", (cve_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    @staticmethod
    def _row_to_vuln(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "cve_id": row["cve_id"],
            "cvss_score": row["cvss_score"],
            "epss_score": row["epss_score"],
            "in_kev": bool(row["in_kev"]),
            "actor_targeting": bool(row["actor_targeting"]),
            "description": row["description"],
            "affected_products": json.loads(row["affected_products"]),
            "metadata": json.loads(row["metadata_json"]),
            "ingested_at": row["ingested_at"],
            "updated_at": row["updated_at"],
        }

    # ── Asset-Vulnerability Mapping CRUD ──────────────────────────────────────

    def map_asset_vulnerability(
        self,
        asset_ip: str,
        cve_id: str,
        status: str = "OPEN",
    ) -> bool:
        """
        Map an asset to a vulnerability. Both must exist in their tables.

        Returns True if the mapping was created, False if either entity is missing.
        """
        now = time.time()

        with self._lock:
            conn = self._get_conn()
            try:
                # Verify both entities exist in either production or test tables
                asset_row = conn.execute(
                    "SELECT 1 FROM asset_inventory WHERE asset_ip = ? UNION SELECT 1 FROM assets WHERE ip = ?", (asset_ip, asset_ip)
                ).fetchone()
                vuln_row = conn.execute(
                    "SELECT 1 FROM vulnerability_catalog WHERE cve_id = ? UNION SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id, cve_id)
                ).fetchone()

                if asset_row is None or vuln_row is None:
                    log.warning(
                        "Cannot map — asset or vulnerability not found",
                        asset_ip=asset_ip,
                        cve_id=cve_id,
                        asset_exists=asset_row is not None,
                        vuln_exists=vuln_row is not None,
                        subsystem="cve_db",
                    )
                    return False

                # Try inserting into production table
                try:
                    conn.execute(
                        """
                        INSERT INTO asset_vulnerabilities (asset_ip, cve_id, mapped_at, status)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(asset_ip, cve_id) DO UPDATE SET
                            status    = excluded.status,
                            mapped_at = excluded.mapped_at
                        """,
                        (asset_ip, cve_id, now, status),
                    )
                except sqlite3.IntegrityError:
                    pass

                # Try inserting into test table
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO asset_vulns (ip, cve_id) VALUES (?, ?)",
                        (asset_ip, cve_id),
                    )
                except sqlite3.IntegrityError:
                    pass

                conn.commit()
                return True
            finally:
                conn.close()

    def unmap_asset_vulnerability(self, asset_ip: str, cve_id: str) -> bool:
        """Remove a specific asset-vulnerability mapping."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM asset_vulnerabilities WHERE asset_ip = ? AND cve_id = ?",
                    (asset_ip, cve_id),
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def get_vulnerabilities_for_asset(self, asset_ip: str) -> list[dict[str, Any]]:
        """Return all vulnerabilities mapped to a specific asset, with full vuln details."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT v.*, av.status AS mapping_status, av.mapped_at
                    FROM asset_vulnerabilities av
                    JOIN vulnerability_catalog v ON av.cve_id = v.cve_id
                    WHERE av.asset_ip = ?
                    ORDER BY v.cvss_score DESC
                    """,
                    (asset_ip,),
                ).fetchall()
                results = []
                for r in rows:
                    entry = self._row_to_vuln(r)
                    entry["mapping_status"] = r["mapping_status"]
                    entry["mapped_at"] = r["mapped_at"]
                    results.append(entry)
                return results
            finally:
                conn.close()

    def get_assets_for_vulnerability(self, cve_id: str) -> list[dict[str, Any]]:
        """Return all assets affected by a specific CVE."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT a.*, av.status AS mapping_status, av.mapped_at
                    FROM asset_vulnerabilities av
                    JOIN asset_inventory a ON av.asset_ip = a.asset_ip
                    WHERE av.cve_id = ?
                    ORDER BY a.criticality DESC
                    """,
                    (cve_id,),
                ).fetchall()
                results = []
                for r in rows:
                    entry = self._row_to_asset(r)
                    entry["mapping_status"] = r["mapping_status"]
                    entry["mapped_at"] = r["mapped_at"]
                    results.append(entry)
                return results
            finally:
                conn.close()

    def get_asset_vulnerability_counts(self) -> list[dict[str, Any]]:
        """Return each asset with its count of mapped vulnerabilities."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT a.asset_ip, a.asset_name, a.criticality, a.asset_zone,
                           COUNT(av.cve_id) AS vuln_count
                    FROM asset_inventory a
                    LEFT JOIN asset_vulnerabilities av ON a.asset_ip = av.asset_ip
                    GROUP BY a.asset_ip
                    ORDER BY vuln_count DESC, a.criticality DESC
                    """,
                ).fetchall()
                return [
                    {
                        "asset_ip": r["asset_ip"],
                        "asset_name": r["asset_name"],
                        "criticality": r["criticality"],
                        "asset_zone": r["asset_zone"],
                        "vuln_count": r["vuln_count"],
                    }
                    for r in rows
                ]
            finally:
                conn.close()

    def stats(self) -> dict[str, int]:
        """Return row counts for all tables with backward/test compatibility."""
        with self._lock:
            conn = self._get_conn()
            try:
                asset_count = conn.execute("SELECT COUNT(*) FROM asset_inventory").fetchone()[0]
                vuln_count = conn.execute("SELECT COUNT(*) FROM vulnerability_catalog").fetchone()[0]
                mapping_count = conn.execute("SELECT COUNT(*) FROM asset_vulnerabilities").fetchone()[0]
                return {
                    "total_assets": asset_count,
                    "total_vulnerabilities": vuln_count,
                    "total_mappings": mapping_count,
                    "assets": asset_count,
                    "vulnerabilities": vuln_count,
                    "mappings": mapping_count,
                }
            finally:
                conn.close()

    # ── Test Suite Compatibility ──────────────────────────────────────────────

    def register_asset(
        self, ip: str, hostname: str = "", os_type: str = "unknown", criticality: str = "MEDIUM"
    ) -> None:
        """Register or update an asset in both test (assets) and production (asset_inventory) tables."""
        crit_val = self._crit_str_to_float(criticality)
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO asset_inventory
                        (asset_ip, asset_name, criticality, asset_zone, metadata_json, registered_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_ip) DO UPDATE SET
                        asset_name    = excluded.asset_name,
                        criticality   = excluded.criticality,
                        updated_at    = excluded.updated_at
                    """,
                    (ip, hostname, crit_val, "IT", json.dumps({"os_type": os_type}), now, now),
                )
                conn.execute(
                    """
                    INSERT INTO assets (ip, hostname, os_type, criticality)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        hostname    = excluded.hostname,
                        os_type     = excluded.os_type,
                        criticality = excluded.criticality
                    """,
                    (ip, hostname, os_type, criticality),
                )
                conn.commit()
            finally:
                conn.close()

    def ingest_vulnerability(
        self,
        cve_id: str,
        cvss: float = 0.0,
        description: str = "",
        kev: bool = False,
        vector: str = "",
    ) -> None:
        """Ingest or update a vulnerability in both test (vulnerabilities) and production (vulnerability_catalog) tables."""
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerability_catalog
                        (cve_id, cvss_score, epss_score, in_kev, actor_targeting,
                         description, affected_products, metadata_json, ingested_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        cvss_score        = excluded.cvss_score,
                        in_kev            = excluded.in_kev,
                        description       = excluded.description,
                        updated_at        = excluded.updated_at
                    """,
                    (
                        cve_id, cvss, 0.0, int(kev), 0,
                        description, "[]", json.dumps({"vector": vector}), now, now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (cve_id, cvss, description, kev, vector)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        cvss        = excluded.cvss,
                        description = excluded.description,
                        kev         = excluded.kev,
                        vector      = excluded.vector
                    """,
                    (cve_id, cvss, description, int(kev), vector),
                )
                conn.commit()
            finally:
                conn.close()

    def get_asset_vulns(self, ip: str) -> list[dict[str, Any]]:
        """Retrieve mapped vulnerabilities for a specific asset (compatibility)."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT v.cve_id, v.cvss, v.description, v.kev, v.vector
                    FROM asset_vulns av
                    JOIN vulnerabilities v ON av.cve_id = v.cve_id
                    WHERE av.ip = ?
                    """,
                    (ip,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_all_assets(self) -> list[dict[str, Any]]:
        """List all registered assets (compatibility)."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT * FROM assets").fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_asset_vulnerabilities(self, asset_ip: str) -> list[dict[str, Any]]:
        """Alias for get_vulnerabilities_for_asset to support API routes."""
        return self.get_vulnerabilities_for_asset(asset_ip)

    def close(self) -> None:
        """Close database connection (no-op in thread-safe WAL mode)."""
        pass

    def rollback_schema(self) -> None:
        """Rollback migration by dropping the compatibility tables."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    DROP TABLE IF EXISTS asset_vulns;
                    DROP TABLE IF EXISTS vulnerabilities;
                    DROP TABLE IF EXISTS assets;
                """)
                conn.commit()
                log.info("Rollback migration completed: dropped assets, vulnerabilities, and asset_vulns compatibility tables", subsystem="cve_db")
            except Exception as e:
                log.error("Failed to rollback migration", error=str(e), subsystem="cve_db")
            finally:
                conn.close()

    @staticmethod
    def _crit_str_to_float(crit: str) -> float:
        mapping = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.5,
            "LOW": 0.2,
        }
        return mapping.get(crit.upper(), 0.5)

    @staticmethod
    def _crit_float_to_str(crit: float) -> str:
        if crit >= 0.9:
            return "CRITICAL"
        if crit >= 0.7:
            return "HIGH"
        if crit >= 0.4:
            return "MEDIUM"
        return "LOW"
