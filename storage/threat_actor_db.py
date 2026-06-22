"""
CNI-Resilience Threat Actor Database
====================================
Stores threat actor mappings, confidence scores, TTPs, and target sectors.
"""

from __future__ import annotations
import sqlite3
import os
from typing import Any, Dict, List
from utils.logger import log

_DB_PATH = os.path.join("data", "logs", "threat_actors.db")

class ThreatActorDatabase:
    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT UNIQUE NOT NULL,
                origin          TEXT,
                description     TEXT,
                target_sectors  TEXT NOT NULL DEFAULT '[]', -- JSON array
                confidence_score REAL DEFAULT 0.5
            );

            CREATE TABLE IF NOT EXISTS actor_ttps (
                actor_name      TEXT,
                technique_id    TEXT,
                confidence      REAL NOT NULL DEFAULT 0.8,
                PRIMARY KEY (actor_name, technique_id),
                FOREIGN KEY (actor_name) REFERENCES threat_actors(name) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_name      TEXT,
                campaign_name   TEXT NOT NULL,
                target_sector   TEXT,
                year            INTEGER,
                description     TEXT,
                FOREIGN KEY (actor_name) REFERENCES threat_actors(name) ON DELETE CASCADE
            );
        """)
        conn.commit()
        
        # Check if empty, seed some default threat actors for the demo
        cur.execute("SELECT COUNT(*) FROM threat_actors")
        if cur.fetchone()[0] == 0:
            self._seed_default_data(cur)
            conn.commit()
            
        conn.close()

    def _seed_default_data(self, cur: sqlite3.Cursor) -> None:
        actors = [
            ("APT-37", "North Korea", "State-sponsored cyber espionage group targeting infrastructure and telecom.", '["ENERGY_GRID", "TELECOM", "GOVERNMENT"]', 0.90),
            ("Lazarus Group", "North Korea", "Highly active state group known for destructive campaigns and financial theft.", '["HEALTHCARE", "GOVERNMENT", "EDUCATION"]', 0.95),
            ("Sandworm", "Russia", "APT group famous for critical infrastructure disruptions (blackouts).", '["ENERGY_GRID", "GOVERNMENT"]', 0.98),
            ("APT-29", "Russia", "Advanced group focused on long-term intelligence gathering.", '["GOVERNMENT", "TELECOM"]', 0.92)
        ]
        cur.executemany(
            "INSERT INTO threat_actors (name, origin, description, target_sectors, confidence_score) VALUES (?, ?, ?, ?, ?)",
            actors
        )

        ttps = [
            ("APT-37", "T1189", 0.90), # Drive-by Compromise
            ("APT-37", "T1566", 0.85), # Phishing
            ("APT-37", "T1059", 0.80), # Command execution
            ("Lazarus Group", "T1190", 0.92), # Exploit public applications
            ("Lazarus Group", "T1588", 0.88), # Obtain Capabilities
            ("Sandworm", "T1078", 0.95), # Valid Accounts
            ("Sandworm", "T1190", 0.90), # SCADA Exploit
            ("APT-29", "T1566", 0.95)
        ]
        cur.executemany(
            "INSERT INTO actor_ttps (actor_name, technique_id, confidence) VALUES (?, ?, ?)",
            ttps
        )

        campaigns = [
            ("APT-37", "Operation Reaper", "TELECOM", 2019, "Targeted mobile and telecom entities in South Asia."),
            ("Sandworm", "BlackEnergy", "ENERGY_GRID", 2015, "Destroyed SCADA systems causing power blackouts."),
            ("Lazarus Group", "WannaCry", "HEALTHCARE", 2017, "Global ransomware campaign locking hospital devices.")
        ]
        cur.executemany(
            "INSERT INTO campaigns (actor_name, campaign_name, target_sector, year, description) VALUES (?, ?, ?, ?, ?)",
            campaigns
        )

    def attribute_ttp_alert(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Attributes a list of observed TTP techniques to known threat actors based on matching counts.
        """
        if not technique_ids:
            return []
            
        conn = self._get_conn()
        cur = conn.cursor()
        
        placeholders = ",".join("?" for _ in technique_ids)
        query = f"""
            SELECT a.name, a.description, a.confidence_score, COUNT(t.technique_id) as matched_count,
                   GROUP_CONCAT(t.technique_id) as matched_ttps
            FROM threat_actors a
            JOIN actor_ttps t ON a.name = t.actor_name
            WHERE t.technique_id IN ({placeholders})
            GROUP BY a.name
            ORDER BY matched_count DESC, a.confidence_score DESC
        """
        
        cur.execute(query, technique_ids)
        rows = cur.fetchall()
        
        results = []
        for row in rows:
            results.append({
                "actor_name": row["name"],
                "description": row["description"],
                "base_confidence": row["confidence_score"],
                "matched_count": row["matched_count"],
                "matched_ttps": row["matched_ttps"].split(",") if row["matched_ttps"] else []
            })
            
        conn.close()
        return results

    def get_actor_profile(self, name: str) -> Dict[str, Any] | None:
        conn = self._get_conn()
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM threat_actors WHERE name = ?", (name,))
        actor_row = cur.fetchone()
        if not actor_row:
            conn.close()
            return None
            
        cur.execute("SELECT technique_id, confidence FROM actor_ttps WHERE actor_name = ?", (name,))
        ttps = [{"technique_id": r["technique_id"], "confidence": r["confidence"]} for r in cur.fetchall()]
        
        cur.execute("SELECT campaign_name, target_sector, year, description FROM campaigns WHERE actor_name = ?", (name,))
        campaigns = [{"name": r["campaign_name"], "sector": r["target_sector"], "year": r["year"], "description": r["description"]} for r in cur.fetchall()]
        
        conn.close()
        
        import json
        return {
            "name": actor_row["name"],
            "origin": actor_row["origin"],
            "description": actor_row["description"],
            "target_sectors": json.loads(actor_row["target_sectors"]),
            "confidence_score": actor_row["confidence_score"],
            "ttps": ttps,
            "campaigns": campaigns
        }
