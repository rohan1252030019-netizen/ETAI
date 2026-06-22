"""
IMMUNEX Advisory Ingestion Pipeline
====================================
Phase 4 — RAG Threat Intelligence feed ingestion and semantic search.

Parses advisories from CISA KEV, NVD CVE, CERT-In, and MITRE ATT&CK STIX
feeds.  Each advisory is chunked at sentence boundaries, embedded with
sentence-transformers (all-MiniLM-L6-v2, 384-dim), and indexed via
FAISS + SQLite for low-latency retrieval.

Air-gapped & CPU-only compatible — gracefully degrades when optional
dependencies are absent.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import numpy as np
from pydantic import BaseModel, Field

from utils.logger import log

# ─── Optional dependency imports ─────────────────────────────────────────────
_FAISS_AVAILABLE = False
_ENCODER_AVAILABLE = False

try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:
    log.info("FAISS not available — advisory search will use SQLite FTS fallback")

try:
    from sentence_transformers import SentenceTransformer
    _ENCODER_AVAILABLE = True
except ImportError:
    log.info("sentence-transformers not available — advisory embedder disabled")


# ─── Constants ────────────────────────────────────────────────────────────────
_EMBEDDING_DIM = 384  # all-MiniLM-L6-v2
_DEFAULT_DB_DIR = os.path.join("data", "advisory")
_DEFAULT_DB_PATH = os.path.join(_DEFAULT_DB_DIR, "advisory_store.db")

# Rough chars-per-token estimate for English prose (conservative)
_CHARS_PER_TOKEN = 4


# ═══════════════════════════════════════════════════════════════════════════════
#  Enums & Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class AdvisorySource(str, Enum):
    """Supported threat intelligence feed sources."""
    CERT_IN = "CERT_IN"
    CISA_KEV = "CISA_KEV"
    MITRE_ATTACK = "MITRE_ATTACK"
    NVD = "NVD"


class Advisory(BaseModel):
    """Normalised representation of a single threat advisory."""
    source: AdvisorySource
    advisory_id: str
    title: str
    description: str
    severity: str = Field(default="UNKNOWN", description="CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN")
    cve_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    published_date: Optional[str] = None
    raw_text: str = ""

    def content_hash(self) -> str:
        """Deterministic SHA-256 digest of the advisory's core content."""
        blob = f"{self.source.value}|{self.advisory_id}|{self.title}|{self.description}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
#  Advisory Parsers
# ═══════════════════════════════════════════════════════════════════════════════

class AdvisoryParser:
    """
    Static methods to parse real-world JSON/text structures from major
    threat intelligence feeds into normalised Advisory objects.
    """

    # ── CISA Known Exploited Vulnerabilities (KEV) ────────────────────────────
    @staticmethod
    def parse_cisa_kev(data: dict) -> list[Advisory]:
        """
        Parse CISA KEV JSON catalog.

        Expected structure (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json):
        {
            "title": "CISA KEV Catalog",
            "catalogVersion": "...",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-XXXX",
                    "vendorProject": "...",
                    "product": "...",
                    "vulnerabilityName": "...",
                    "shortDescription": "...",
                    "dateAdded": "2024-01-01",
                    "dueDate": "2024-01-22",
                    "requiredAction": "...",
                    "knownRansomwareCampaignUse": "Known" | "Unknown",
                    "notes": "..."
                }, ...
            ]
        }
        """
        advisories: list[Advisory] = []
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities and isinstance(data, list):
            # Caller may have passed the list directly
            vulnerabilities = data

        for vuln in vulnerabilities:
            try:
                cve_id = vuln.get("cveID", "").strip()
                vendor = vuln.get("vendorProject", "")
                product = vuln.get("product", "")
                name = vuln.get("vulnerabilityName", cve_id)
                desc = vuln.get("shortDescription", "")
                date_added = vuln.get("dateAdded", "")
                action = vuln.get("requiredAction", "")
                ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
                notes = vuln.get("notes", "")

                # Assign severity heuristic: ransomware-related → CRITICAL
                severity = "CRITICAL" if ransomware == "Known" else "HIGH"

                raw_parts = [
                    f"CVE: {cve_id}",
                    f"Vendor: {vendor} — {product}",
                    f"Name: {name}",
                    f"Description: {desc}",
                    f"Required Action: {action}",
                    f"Ransomware Use: {ransomware}",
                ]
                if notes:
                    raw_parts.append(f"Notes: {notes}")

                advisories.append(Advisory(
                    source=AdvisorySource.CISA_KEV,
                    advisory_id=f"CISA-KEV-{cve_id}" if cve_id else f"CISA-KEV-{uuid.uuid4().hex[:8]}",
                    title=f"{vendor} {product}: {name}",
                    description=desc,
                    severity=severity,
                    cve_ids=[cve_id] if cve_id else [],
                    mitre_techniques=[],
                    published_date=date_added,
                    raw_text="\n".join(raw_parts),
                ))
            except Exception as exc:
                log.warning("Failed to parse CISA KEV entry", error=str(exc))
        log.info("Parsed CISA KEV advisories", count=len(advisories))
        return advisories

    # ── NVD CVE API ───────────────────────────────────────────────────────────
    @staticmethod
    def parse_nvd_cve(data: dict) -> list[Advisory]:
        """
        Parse NVD CVE 2.0 API response.

        Expected structure (https://services.nvd.nist.gov/rest/json/cves/2.0):
        {
            "resultsPerPage": 20,
            "startIndex": 0,
            "totalResults": 100,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-XXXX",
                        "descriptions": [{"lang": "en", "value": "..."}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                                ...
                            }]
                        },
                        "weaknesses": [...],
                        "references": [...],
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "..."
                    }
                }, ...
            ]
        }
        """
        advisories: list[Advisory] = []
        vulns = data.get("vulnerabilities", [])

        for entry in vulns:
            try:
                cve_obj = entry.get("cve", entry)  # handle both wrappers
                cve_id = cve_obj.get("id", "")

                # English description
                descriptions = cve_obj.get("descriptions", [])
                desc_en = ""
                for d in descriptions:
                    if d.get("lang", "en") == "en":
                        desc_en = d.get("value", "")
                        break
                if not desc_en and descriptions:
                    desc_en = descriptions[0].get("value", "")

                # CVSS severity
                severity = "UNKNOWN"
                base_score = 0.0
                metrics = cve_obj.get("metrics", {})
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        base_score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                        break

                published = cve_obj.get("published", "")

                raw_text = (
                    f"CVE: {cve_id}\n"
                    f"CVSS Score: {base_score}\n"
                    f"Severity: {severity}\n"
                    f"Description: {desc_en}\n"
                    f"Published: {published}"
                )

                advisories.append(Advisory(
                    source=AdvisorySource.NVD,
                    advisory_id=f"NVD-{cve_id}",
                    title=cve_id,
                    description=desc_en,
                    severity=severity,
                    cve_ids=[cve_id] if cve_id else [],
                    mitre_techniques=[],
                    published_date=published[:10] if published else None,
                    raw_text=raw_text,
                ))
            except Exception as exc:
                log.warning("Failed to parse NVD CVE entry", error=str(exc))
        log.info("Parsed NVD CVE advisories", count=len(advisories))
        return advisories

    # ── CERT-In text advisories ───────────────────────────────────────────────
    @staticmethod
    def parse_cert_in(text: str) -> list[Advisory]:
        """
        Parse CERT-In advisory text bulletins.

        Typical structure:
            Advisory Number: CIAD-2024-0001
            Date: January 15, 2024
            Severity: HIGH
            Subject: Multiple Vulnerabilities in <Product>
            CVE: CVE-2024-1234, CVE-2024-1235
            Description:
            ...multi-line description...
            Solution / Workaround:
            ...
            References:
            ...
        Multiple advisories can appear in a single document separated by
        "Advisory Number:" headers.
        """
        advisories: list[Advisory] = []

        # Split on "Advisory Number:" headers
        blocks = re.split(r"(?=Advisory\s+Number\s*:)", text, flags=re.IGNORECASE)

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            # Extract fields
            adv_id_match = re.search(
                r"Advisory\s+Number\s*:\s*(.+)", block, re.IGNORECASE
            )
            date_match = re.search(r"Date\s*:\s*(.+)", block, re.IGNORECASE)
            severity_match = re.search(r"Severity\s*:\s*(\w+)", block, re.IGNORECASE)
            subject_match = re.search(r"Subject\s*:\s*(.+)", block, re.IGNORECASE)

            # CVEs
            cve_ids: list[str] = re.findall(r"CVE-\d{4}-\d{4,}", block)

            # Description block
            desc_match = re.search(
                r"Description\s*:\s*\n(.*?)(?=\n\s*(?:Solution|Workaround|Reference|Recommendation|Impact)\s*:|\Z)",
                block,
                re.DOTALL | re.IGNORECASE,
            )
            description = desc_match.group(1).strip() if desc_match else block[:500]

            adv_id = adv_id_match.group(1).strip() if adv_id_match else f"CERT-IN-{uuid.uuid4().hex[:8]}"
            title = subject_match.group(1).strip() if subject_match else f"CERT-In Advisory {adv_id}"
            severity = (severity_match.group(1).strip().upper() if severity_match else "MEDIUM")
            pub_date = date_match.group(1).strip() if date_match else None

            advisories.append(Advisory(
                source=AdvisorySource.CERT_IN,
                advisory_id=adv_id,
                title=title,
                description=description,
                severity=severity,
                cve_ids=list(set(cve_ids)),
                mitre_techniques=[],
                published_date=pub_date,
                raw_text=block,
            ))
        log.info("Parsed CERT-In advisories", count=len(advisories))
        return advisories

    # ── MITRE ATT&CK STIX bundle ─────────────────────────────────────────────
    @staticmethod
    def parse_mitre_attack(data: dict) -> list[Advisory]:
        """
        Parse a MITRE ATT&CK STIX 2.1 bundle.

        Expected structure:
        {
            "type": "bundle",
            "id": "bundle--...",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--...",
                    "name": "Phishing",
                    "description": "...",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1566"},
                        {"source_name": "...", "url": "..."}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ],
                    "created": "...",
                    "modified": "..."
                }, ...
            ]
        }
        """
        advisories: list[Advisory] = []
        objects = data.get("objects", [])

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            try:
                name = obj.get("name", "Unknown Technique")
                description = obj.get("description", "")
                created = obj.get("created", "")
                modified = obj.get("modified", "")

                # Extract ATT&CK technique IDs (e.g. T1566, T1566.001)
                ext_refs = obj.get("external_references", [])
                technique_ids: list[str] = []
                cve_ids: list[str] = []
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "")
                        if ext_id:
                            technique_ids.append(ext_id)
                    # Some references include CVEs
                    desc_text = ref.get("description", "")
                    cve_ids.extend(re.findall(r"CVE-\d{4}-\d{4,}", desc_text))

                # Kill-chain phases → severity heuristic
                phases = obj.get("kill_chain_phases", [])
                phase_names = [p.get("phase_name", "") for p in phases]

                severity = "MEDIUM"
                high_impact_phases = {
                    "privilege-escalation", "defense-evasion",
                    "credential-access", "lateral-movement", "exfiltration",
                    "impact",
                }
                if any(p in high_impact_phases for p in phase_names):
                    severity = "HIGH"
                if "impact" in phase_names:
                    severity = "CRITICAL"

                tech_label = ", ".join(technique_ids) if technique_ids else "N/A"
                raw_text = (
                    f"Technique: {tech_label} — {name}\n"
                    f"Kill Chain Phases: {', '.join(phase_names)}\n"
                    f"Description: {description}\n"
                    f"Created: {created} | Modified: {modified}"
                )

                advisories.append(Advisory(
                    source=AdvisorySource.MITRE_ATTACK,
                    advisory_id=f"MITRE-{technique_ids[0]}" if technique_ids else f"MITRE-{uuid.uuid4().hex[:8]}",
                    title=f"{tech_label}: {name}",
                    description=description,
                    severity=severity,
                    cve_ids=list(set(cve_ids)),
                    mitre_techniques=technique_ids,
                    published_date=created[:10] if created else None,
                    raw_text=raw_text,
                ))
            except Exception as exc:
                log.warning("Failed to parse MITRE ATT&CK object", error=str(exc))
        log.info("Parsed MITRE ATT&CK techniques", count=len(advisories))
        return advisories


# ═══════════════════════════════════════════════════════════════════════════════
#  Advisory Chunker
# ═══════════════════════════════════════════════════════════════════════════════

class AdvisoryChunker:
    """
    Splits advisory text into overlapping chunks at sentence boundaries,
    respecting a token budget.
    """

    # Regex that splits on sentence-ending punctuation followed by whitespace
    _SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")

    @classmethod
    def chunk_advisory(
        cls,
        advisory: Advisory,
        max_tokens: int = 512,
        overlap: int = 64,
    ) -> list[str]:
        """
        Split *advisory* raw_text (falling back to description) into chunks.

        Parameters
        ----------
        advisory : Advisory
            The advisory to chunk.
        max_tokens : int
            Maximum token budget per chunk (estimated via char heuristic).
        overlap : int
            Number of overlap tokens between consecutive chunks.

        Returns
        -------
        list[str]
            Ordered list of text chunks with metadata header prepended.
        """
        text = advisory.raw_text.strip() or advisory.description.strip()
        if not text:
            return []

        # Prepend a metadata header so every chunk is self-identifying
        header = (
            f"[{advisory.source.value}] {advisory.advisory_id} | "
            f"Severity: {advisory.severity} | "
            f"CVEs: {', '.join(advisory.cve_ids) if advisory.cve_ids else 'N/A'}"
        )

        sentences = cls._SENTENCE_RE.split(text)
        sentences = [s.strip() for s in sentences if s.strip()]

        if not sentences:
            return [f"{header}\n{text}"]

        max_chars = max_tokens * _CHARS_PER_TOKEN
        overlap_chars = overlap * _CHARS_PER_TOKEN

        chunks: list[str] = []
        current_sentences: list[str] = []
        current_len = 0

        for sentence in sentences:
            sentence_len = len(sentence)
            if current_len + sentence_len > max_chars and current_sentences:
                chunk_text = " ".join(current_sentences)
                chunks.append(f"{header}\n{chunk_text}")

                # Build overlap from the tail of current sentences
                overlap_sentences: list[str] = []
                overlap_len = 0
                for s in reversed(current_sentences):
                    if overlap_len + len(s) > overlap_chars:
                        break
                    overlap_sentences.insert(0, s)
                    overlap_len += len(s)

                current_sentences = overlap_sentences
                current_len = overlap_len

            current_sentences.append(sentence)
            current_len += sentence_len

        # Flush remaining
        if current_sentences:
            chunk_text = " ".join(current_sentences)
            chunks.append(f"{header}\n{chunk_text}")

        return chunks


# ═══════════════════════════════════════════════════════════════════════════════
#  Advisory Embedder
# ═══════════════════════════════════════════════════════════════════════════════

class AdvisoryEmbedder:
    """
    Wraps sentence-transformers for encoding advisory chunks and queries.
    Falls back to a deterministic random projection when the model is
    unavailable (useful for testing in air-gapped environments).
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._encoder: Any = None
        self._model_name = model_name
        if _ENCODER_AVAILABLE:
            try:
                self._encoder = SentenceTransformer(model_name)
                log.info("AdvisoryEmbedder loaded", model=model_name)
            except Exception as exc:
                log.warning(
                    "AdvisoryEmbedder model load failed — using hash fallback",
                    error=str(exc),
                )
        else:
            log.info("AdvisoryEmbedder using deterministic hash fallback")

    # ── Public API ────────────────────────────────────────────────────────────

    def embed_chunks(self, chunks: list[str]) -> np.ndarray:
        """
        Encode a list of text chunks into a (N, 384) float32 matrix.

        Returns
        -------
        np.ndarray
            Shape ``(len(chunks), 384)`` normalised embeddings.
        """
        if not chunks:
            return np.empty((0, _EMBEDDING_DIM), dtype=np.float32)
        if self._encoder is not None:
            embeddings = self._encoder.encode(chunks, show_progress_bar=False)
            embeddings = np.asarray(embeddings, dtype=np.float32)
        else:
            embeddings = self._hash_encode(chunks)

        # L2-normalise for cosine-similarity via inner-product search
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        embeddings = embeddings / norms
        return embeddings

    def embed_query(self, query: str) -> np.ndarray:
        """
        Encode a single query string into a (1, 384) normalised vector.
        """
        return self.embed_chunks([query])

    # ── Fallback ──────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_encode(texts: list[str]) -> np.ndarray:
        """Deterministic pseudo-embedding derived from SHA-256 for testing."""
        vecs = []
        for t in texts:
            digest = hashlib.sha256(t.encode("utf-8")).digest()
            # Repeat digest bytes to fill 384 floats (384 * 4 = 1536 bytes)
            extended = (digest * 48)[:_EMBEDDING_DIM * 4]
            vec = np.frombuffer(extended, dtype=np.float32).copy()
            vec = vec[:_EMBEDDING_DIM]
            vecs.append(vec)
        return np.stack(vecs).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════════════════
#  Advisory Ingestion Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

class AdvisoryIngestionPipeline:
    """
    End-to-end pipeline: parse → chunk → embed → store (SQLite + FAISS).

    Provides feed-specific ingestion helpers and a unified semantic search
    interface over all ingested advisories.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

        self._embedder = AdvisoryEmbedder()

        # FAISS inner-product index (cosine similarity on L2-normed vectors)
        self._faiss_index: Any = None
        self._chunk_id_map: list[int] = []  # FAISS row → chunk rowid

        if _FAISS_AVAILABLE:
            try:
                self._faiss_index = faiss.IndexFlatIP(_EMBEDDING_DIM)
                # Rebuild index from existing DB rows on init
                self._rebuild_faiss_index()
                log.info(
                    "AdvisoryIngestionPipeline FAISS index ready",
                    vectors=self._faiss_index.ntotal,
                )
            except Exception as exc:
                log.warning("FAISS init failed in advisory pipeline", error=str(exc))
        log.info("AdvisoryIngestionPipeline initialized", db_path=db_path)

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        """Create SQLite tables for advisories and their chunked embeddings."""
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS advisories (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                advisory_id   TEXT UNIQUE,
                source        TEXT NOT NULL,
                title         TEXT,
                description   TEXT,
                severity      TEXT,
                cve_ids       TEXT,          -- JSON array
                mitre_techniques TEXT,       -- JSON array
                published_date TEXT,
                raw_text      TEXT,
                content_hash  TEXT,
                ingested_at   REAL
            );

            CREATE INDEX IF NOT EXISTS idx_adv_source   ON advisories(source);
            CREATE INDEX IF NOT EXISTS idx_adv_severity  ON advisories(severity);
            CREATE INDEX IF NOT EXISTS idx_adv_pub_date  ON advisories(published_date);

            CREATE TABLE IF NOT EXISTS advisory_chunks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                advisory_id   TEXT NOT NULL,
                chunk_index   INTEGER NOT NULL,
                chunk_text    TEXT NOT NULL,
                embedding     BLOB,          -- raw float32 bytes
                FOREIGN KEY (advisory_id) REFERENCES advisories(advisory_id)
            );

            CREATE INDEX IF NOT EXISTS idx_chunk_adv ON advisory_chunks(advisory_id);
        """)
        # FTS5 for full-text fallback search
        try:
            cur.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS advisory_fts
                USING fts5(
                    advisory_id, title, description, raw_text,
                    content=advisories, content_rowid=id
                );
            """)
        except Exception:
            log.debug("advisory_fts already exists or FTS5 not supported")
        self._conn.commit()

    # ── FAISS index rebuild from SQLite ───────────────────────────────────────

    def _rebuild_faiss_index(self) -> None:
        """Load existing embeddings from SQLite into FAISS at startup."""
        if self._faiss_index is None:
            return
        cur = self._conn.cursor()
        cur.execute("SELECT id, embedding FROM advisory_chunks WHERE embedding IS NOT NULL")
        rows = cur.fetchall()
        if not rows:
            return
        ids: list[int] = []
        vecs: list[np.ndarray] = []
        for row in rows:
            blob = row["embedding"]
            if blob is None:
                continue
            vec = np.frombuffer(blob, dtype=np.float32).copy()
            if vec.shape[0] == _EMBEDDING_DIM:
                vecs.append(vec)
                ids.append(row["id"])
        if vecs:
            matrix = np.stack(vecs)
            self._faiss_index.add(matrix)
            self._chunk_id_map.extend(ids)

    # ── Internal ingestion helper ─────────────────────────────────────────────

    def _ingest_advisories(self, advisories: list[Advisory]) -> int:
        """Chunk, embed, and store a batch of parsed advisories."""
        import json as _json

        count = 0
        cur = self._conn.cursor()
        for adv in advisories:
            try:
                # Upsert advisory metadata
                cur.execute("""
                    INSERT OR REPLACE INTO advisories
                    (advisory_id, source, title, description, severity,
                     cve_ids, mitre_techniques, published_date, raw_text,
                     content_hash, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    adv.advisory_id,
                    adv.source.value,
                    adv.title,
                    adv.description,
                    adv.severity,
                    _json.dumps(adv.cve_ids),
                    _json.dumps(adv.mitre_techniques),
                    adv.published_date,
                    adv.raw_text,
                    adv.content_hash(),
                    time.time(),
                ))
                # Populate FTS
                try:
                    rowid = cur.lastrowid
                    cur.execute("""
                        INSERT INTO advisory_fts(rowid, advisory_id, title, description, raw_text)
                        VALUES (?, ?, ?, ?, ?)
                    """, (rowid, adv.advisory_id, adv.title, adv.description, adv.raw_text))
                except Exception:
                    pass

                # Chunk and embed
                chunks = AdvisoryChunker.chunk_advisory(adv)
                if not chunks:
                    count += 1
                    continue

                embeddings = self._embedder.embed_chunks(chunks)

                # Delete old chunks for this advisory (idempotent re-ingestion)
                cur.execute("DELETE FROM advisory_chunks WHERE advisory_id = ?", (adv.advisory_id,))

                for idx, (chunk_text, emb_vec) in enumerate(zip(chunks, embeddings)):
                    emb_blob = emb_vec.tobytes()
                    cur.execute("""
                        INSERT INTO advisory_chunks (advisory_id, chunk_index, chunk_text, embedding)
                        VALUES (?, ?, ?, ?)
                    """, (adv.advisory_id, idx, chunk_text, emb_blob))
                    chunk_rowid = cur.lastrowid

                    # Index in FAISS
                    if self._faiss_index is not None:
                        self._faiss_index.add(emb_vec.reshape(1, -1))
                        self._chunk_id_map.append(chunk_rowid)

                count += 1
            except Exception as exc:
                log.warning("Advisory ingestion failed", advisory_id=adv.advisory_id, error=str(exc))
        self._conn.commit()
        log.info("Advisory batch ingested", stored=count, total=len(advisories))
        return count

    # ── Feed-specific ingestion entry points ──────────────────────────────────

    def ingest_cisa_kev(self, json_data: dict) -> int:
        """Parse and ingest CISA KEV JSON catalog. Returns count ingested."""
        advisories = AdvisoryParser.parse_cisa_kev(json_data)
        return self._ingest_advisories(advisories)

    def ingest_nvd_cves(self, json_data: dict) -> int:
        """Parse and ingest NVD CVE API response. Returns count ingested."""
        advisories = AdvisoryParser.parse_nvd_cve(json_data)
        return self._ingest_advisories(advisories)

    def ingest_cert_in(self, text: str) -> int:
        """Parse and ingest CERT-In text bulletins. Returns count ingested."""
        advisories = AdvisoryParser.parse_cert_in(text)
        return self._ingest_advisories(advisories)

    def ingest_mitre_attack(self, stix_data: dict) -> int:
        """Parse and ingest MITRE ATT&CK STIX bundle. Returns count ingested."""
        advisories = AdvisoryParser.parse_mitre_attack(stix_data)
        return self._ingest_advisories(advisories)

    # ── Search ────────────────────────────────────────────────────────────────

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """
        Semantic search over ingested advisory chunks.

        Returns a list of dicts with keys: ``advisory_id``, ``text``, ``score``.
        Falls back to FTS / LIKE when FAISS is unavailable.
        """
        # ── Vector search via FAISS ───────────────────────────────────────────
        if (
            self._faiss_index is not None
            and self._faiss_index.ntotal > 0
        ):
            try:
                query_vec = self._embedder.embed_query(query)
                k = min(top_k, self._faiss_index.ntotal)
                scores, indices = self._faiss_index.search(query_vec, k)
                results: list[dict] = []
                cur = self._conn.cursor()
                for score, idx in zip(scores[0], indices[0]):
                    if idx < 0 or idx >= len(self._chunk_id_map):
                        continue
                    chunk_rowid = self._chunk_id_map[idx]
                    cur.execute(
                        "SELECT advisory_id, chunk_text FROM advisory_chunks WHERE id = ?",
                        (chunk_rowid,),
                    )
                    row = cur.fetchone()
                    if row:
                        results.append({
                            "advisory_id": row["advisory_id"],
                            "text": row["chunk_text"],
                            "score": round(float(score), 4),
                        })
                if results:
                    return results
            except Exception as exc:
                log.debug("FAISS search failed, falling back to SQLite", error=str(exc))

        # ── FTS5 fallback ─────────────────────────────────────────────────────
        try:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT advisory_id, raw_text
                FROM advisory_fts
                WHERE advisory_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """, (query, top_k))
            rows = cur.fetchall()
            if rows:
                return [
                    {"advisory_id": r["advisory_id"], "text": r["raw_text"], "score": 0.0}
                    for r in rows
                ]
        except Exception:
            pass

        # ── LIKE fallback ─────────────────────────────────────────────────────
        keywords = query.split()
        if not keywords:
            return []
        conditions = " OR ".join(["raw_text LIKE ?"] * len(keywords))
        params: list[Any] = [f"%{kw}%" for kw in keywords]
        params.append(top_k)
        try:
            cur = self._conn.cursor()
            cur.execute(f"""
                SELECT advisory_id, raw_text
                FROM advisories
                WHERE {conditions}
                ORDER BY ingested_at DESC
                LIMIT ?
            """, params)
            return [
                {"advisory_id": r["advisory_id"], "text": r["raw_text"], "score": 0.0}
                for r in cur.fetchall()
            ]
        except Exception:
            return []

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """
        Return ingestion statistics: total advisories, counts per source,
        total chunks, and FAISS vector count.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) AS total FROM advisories")
        total = cur.fetchone()["total"]

        cur.execute("SELECT source, COUNT(*) AS cnt FROM advisories GROUP BY source")
        per_source = {r["source"]: r["cnt"] for r in cur.fetchall()}

        cur.execute("SELECT COUNT(*) AS total FROM advisory_chunks")
        total_chunks = cur.fetchone()["total"]

        return {
            "total_advisories": total,
            "per_source": per_source,
            "total_chunks": total_chunks,
            "faiss_vectors": self._faiss_index.ntotal if self._faiss_index else 0,
            "faiss_available": _FAISS_AVAILABLE,
            "encoder_available": _ENCODER_AVAILABLE,
            "db_path": self._db_path,
        }
