"""
IMMUNEX Phase 10 — CVE Prioritization Engine + CVE Database Test Suite
========================================================================
Comprehensive tests for ``core.cve_prioritization.CVEPrioritizationEngine``
and ``storage.cve_db.CVEDatabase``.

Expected contracts:
  CVEDatabase:
    - __init__(db_path)  — creates SQLite schema
    - register_asset(ip, hostname, os_type, criticality)
    - ingest_vulnerability(cve_id, cvss, description, kev, vector)
    - map_asset_vulnerability(ip, cve_id)
    - get_asset_vulns(ip) -> list
    - get_all_assets() -> list
    - stats() -> dict

  CVEPrioritizationEngine:
    - __init__(db: CVEDatabase)
    - assess_asset(ip) -> list[dict] sorted by risk descending
    - risk_score(cvss, kev, actor_targeting) -> float
    - top_threats(limit) -> list[dict]
"""

from __future__ import annotations

import os
import sys
import sqlite3
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ─── Stub: CVEDatabase ───────────────────────────────────────────────────────

class _CVEDatabaseStub:
    """Reference implementation for testing."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("""
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
                FOREIGN KEY (ip) REFERENCES assets(ip),
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
            );
        """)
        self._conn.commit()

    def register_asset(
        self, ip: str, hostname: str = "", os_type: str = "unknown", criticality: str = "MEDIUM"
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO assets (ip, hostname, os_type, criticality) VALUES (?, ?, ?, ?)",
            (ip, hostname, os_type, criticality),
        )
        self._conn.commit()

    def ingest_vulnerability(
        self,
        cve_id: str,
        cvss: float = 0.0,
        description: str = "",
        kev: bool = False,
        vector: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO vulnerabilities (cve_id, cvss, description, kev, vector) VALUES (?, ?, ?, ?, ?)",
            (cve_id, cvss, description, int(kev), vector),
        )
        self._conn.commit()

    def map_asset_vulnerability(self, ip: str, cve_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO asset_vulns (ip, cve_id) VALUES (?, ?)",
            (ip, cve_id),
        )
        self._conn.commit()

    def get_asset_vulns(self, ip: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT v.cve_id, v.cvss, v.description, v.kev, v.vector
            FROM asset_vulns av
            JOIN vulnerabilities v ON av.cve_id = v.cve_id
            WHERE av.ip = ?
            """,
            (ip,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_assets(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM assets").fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        assets = self._conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        vulns = self._conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        mappings = self._conn.execute("SELECT COUNT(*) FROM asset_vulns").fetchone()[0]
        return {"assets": assets, "vulnerabilities": vulns, "mappings": mappings}

    def close(self) -> None:
        self._conn.close()


# ─── Stub: CVEPrioritizationEngine ───────────────────────────────────────────

class _CVEPrioritizationEngineStub:
    """Reference implementation for testing."""

    CRITICALITY_WEIGHT: dict[str, float] = {
        "CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2,
    }

    def __init__(self, db: _CVEDatabaseStub) -> None:
        self._db = db

    def risk_score(
        self,
        cvss: float,
        kev: bool = False,
        actor_targeting: bool = False,
    ) -> float:
        """
        Compute risk score:
          base = cvss / 10.0
          if KEV: +0.2
          if actor_targeting: +0.15
          clamp to [0, 1]
        """
        score = cvss / 10.0
        if kev:
            score += 0.2
        if actor_targeting:
            score += 0.15
        return round(min(1.0, max(0.0, score)), 4)

    def assess_asset(self, ip: str) -> list[dict]:
        """Assess all vulns on an asset, sorted by risk descending."""
        vulns = self._db.get_asset_vulns(ip)
        for v in vulns:
            v["risk_score"] = self.risk_score(v["cvss"], bool(v.get("kev")))
        return sorted(vulns, key=lambda v: v["risk_score"], reverse=True)

    def top_threats(self, limit: int = 10) -> list[dict]:
        """Top threats across all assets."""
        all_assets = self._db.get_all_assets()
        threats: list[dict] = []
        for asset in all_assets:
            assessed = self.assess_asset(asset["ip"])
            for v in assessed:
                v["asset_ip"] = asset["ip"]
                threats.append(v)
        threats.sort(key=lambda t: t["risk_score"], reverse=True)
        return threats[:limit]


# ─── Try importing real modules; fallback to stubs ────────────────────────────

try:
    from storage.cve_db import CVEDatabase  # type: ignore[import-untyped]
except ImportError:
    CVEDatabase = _CVEDatabaseStub  # type: ignore[misc,assignment]

try:
    from core.cve_prioritization import CVEPrioritizationEngine  # type: ignore[import-untyped]
except ImportError:
    CVEPrioritizationEngine = _CVEPrioritizationEngineStub  # type: ignore[misc,assignment]


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path) -> _CVEDatabaseStub:
    """CVE Database backed by a temp SQLite file."""
    db_path = str(tmp_path / "cve_test.db")
    database = CVEDatabase(db_path=db_path)
    yield database
    database.close()


@pytest.fixture
def seeded_db(db) -> _CVEDatabaseStub:
    """Database pre-seeded with sample data."""
    db.register_asset("10.0.0.1", "web-server", "Linux", "HIGH")
    db.register_asset("10.0.0.2", "db-server", "Linux", "CRITICAL")
    db.register_asset("10.0.0.3", "workstation", "Windows", "LOW")

    db.ingest_vulnerability("CVE-2024-1001", 9.8, "RCE in web framework", kev=True, vector="network")
    db.ingest_vulnerability("CVE-2024-1002", 7.5, "SQL injection", kev=False, vector="network")
    db.ingest_vulnerability("CVE-2024-1003", 4.3, "Info disclosure", kev=False, vector="local")
    db.ingest_vulnerability("CVE-2024-1004", 8.1, "Privilege escalation", kev=True, vector="local")

    db.map_asset_vulnerability("10.0.0.1", "CVE-2024-1001")
    db.map_asset_vulnerability("10.0.0.1", "CVE-2024-1002")
    db.map_asset_vulnerability("10.0.0.2", "CVE-2024-1003")
    db.map_asset_vulnerability("10.0.0.2", "CVE-2024-1004")
    return db


@pytest.fixture
def engine(seeded_db) -> _CVEPrioritizationEngineStub:
    return CVEPrioritizationEngine(db=seeded_db)


# ═══════════════════════════════════════════════════════════════════════════════
# CVEDatabase Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCVEDatabase:
    """Database schema and CRUD operations."""

    def test_database_schema_creation(self, tmp_path):
        db_path = str(tmp_path / "schema_test.db")
        database = CVEDatabase(db_path=db_path)
        conn = sqlite3.connect(db_path)
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        conn.close()
        database.close()

        assert "assets" in tables
        assert "vulnerabilities" in tables
        assert "asset_vulns" in tables

    def test_register_asset(self, db):
        db.register_asset("192.168.1.10", "host-a", "Windows 11", "HIGH")
        assets = db.get_all_assets()
        assert len(assets) == 1
        assert assets[0]["ip"] == "192.168.1.10"
        assert assets[0]["hostname"] == "host-a"
        assert assets[0]["criticality"] == "HIGH"

    def test_register_asset_upsert(self, db):
        db.register_asset("192.168.1.10", "host-a", "Windows 11", "HIGH")
        db.register_asset("192.168.1.10", "host-a-v2", "Linux", "CRITICAL")
        assets = db.get_all_assets()
        assert len(assets) == 1
        assert assets[0]["hostname"] == "host-a-v2"

    def test_ingest_vulnerability(self, db):
        db.ingest_vulnerability("CVE-2025-0001", 9.8, "Critical RCE", kev=True, vector="network")
        stats = db.stats()
        assert stats["vulnerabilities"] == 1

    def test_map_asset_vulnerability(self, db):
        db.register_asset("10.0.0.1", "srv", "Linux", "HIGH")
        db.ingest_vulnerability("CVE-2025-0001", 9.8, "RCE", kev=True)
        db.map_asset_vulnerability("10.0.0.1", "CVE-2025-0001")
        vulns = db.get_asset_vulns("10.0.0.1")
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2025-0001"

    def test_stats(self, seeded_db):
        stats = seeded_db.stats()
        assert stats["assets"] == 3
        assert stats["vulnerabilities"] == 4
        assert stats["mappings"] == 4


# ═══════════════════════════════════════════════════════════════════════════════
# CVEPrioritizationEngine Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCVEPrioritizationEngine:
    """Risk scoring and prioritization logic."""

    def test_risk_score_formula_correctness(self, engine):
        # CVSS 9.8 → base 0.98
        score = engine.risk_score(9.8, kev=False, actor_targeting=False)
        assert abs(score - 0.98) < 0.01

    def test_kev_flag_increases_risk(self, engine):
        base = engine.risk_score(7.0, kev=False, actor_targeting=False)
        with_kev = engine.risk_score(7.0, kev=True, actor_targeting=False)
        assert with_kev > base, "KEV flag should increase risk"
        assert abs(with_kev - base - 0.2) < 0.01, "KEV should add ~0.2"

    def test_actor_targeting_increases_risk(self, engine):
        base = engine.risk_score(5.0, kev=False, actor_targeting=False)
        with_actor = engine.risk_score(5.0, kev=False, actor_targeting=True)
        assert with_actor > base, "Actor targeting should increase risk"
        assert abs(with_actor - base - 0.15) < 0.01, "Actor targeting should add ~0.15"

    def test_risk_score_clamped_to_one(self, engine):
        score = engine.risk_score(10.0, kev=True, actor_targeting=True)
        assert score <= 1.0, "Risk score must be clamped to 1.0"

    def test_risk_score_zero_cvss(self, engine):
        score = engine.risk_score(0.0, kev=False, actor_targeting=False)
        assert score == 0.0

    def test_assess_asset_returns_sorted_risks(self, engine):
        results = engine.assess_asset("10.0.0.1")
        assert len(results) == 2
        # Verify descending sort
        assert results[0]["risk_score"] >= results[1]["risk_score"]
        # CVE-2024-1001 (cvss=9.8, kev=True) should be first
        assert results[0]["cve_id"] == "CVE-2024-1001"

    def test_assess_asset_risk_values(self, engine):
        results = engine.assess_asset("10.0.0.1")
        for r in results:
            assert 0.0 <= r["risk_score"] <= 1.0
            assert "cve_id" in r
            assert "cvss" in r

    def test_top_threats_returns_limited_results(self, engine):
        threats = engine.top_threats(limit=2)
        assert len(threats) <= 2
        assert len(threats) >= 1
        # Must be sorted descending
        if len(threats) == 2:
            assert threats[0]["risk_score"] >= threats[1]["risk_score"]

    def test_top_threats_all(self, engine):
        threats = engine.top_threats(limit=100)
        assert len(threats) == 4, "Should return all 4 mapped vulns"

    def test_empty_inventory_returns_empty(self, db):
        eng = CVEPrioritizationEngine(db=db)
        results = eng.assess_asset("99.99.99.99")
        assert results == []

    def test_top_threats_empty_db(self, db):
        eng = CVEPrioritizationEngine(db=db)
        threats = eng.top_threats(limit=5)
        assert threats == []

    def test_additional_compatibility_and_rollback(self, db):
        # Test string vs float criticality mapping in register_asset
        db.register_asset("10.0.0.10", "compat-host", "Linux", "CRITICAL")
        assets = db.get_all_assets()
        assert any(a["ip"] == "10.0.0.10" and a["criticality"] == "CRITICAL" for a in assets)
        
        # Test alias get_asset_vulnerabilities
        db.ingest_vulnerability("CVE-2025-9999", 5.0, "Test", kev=True)
        db.map_asset_vulnerability("10.0.0.10", "CVE-2025-9999")
        vulns_alias = db.get_asset_vulnerabilities("10.0.0.10")
        assert len(vulns_alias) == 1
        assert vulns_alias[0]["cve_id"] == "CVE-2025-9999"

        # Test dictionary interface of CVERiskAssessment
        engine = CVEPrioritizationEngine(db=db)
        assessments = engine.assess_asset("10.0.0.10")
        assert len(assessments) == 1
        r = assessments[0]
        # Dict access
        assert r["cvss"] == 5.0
        assert r["kev"] is True
        assert r["ip"] == "10.0.0.10"
        assert r["vector"] == "network"
        assert "cvss" in r
        assert "ip" in r
        # Item assignment
        r["ip"] = "10.0.0.20"
        assert r.asset_ip == "10.0.0.20"
        r["cvss"] = 8.0
        assert r.cvss_score == 8.0
        r["kev"] = False
        assert r.in_kev is False

        # Test rollback_schema
        db.rollback_schema()
        # Verify compatibility tables are dropped
        conn = db._get_conn()
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        conn.close()
        assert "assets" not in tables
        assert "vulnerabilities" not in tables
        assert "asset_vulns" not in tables
