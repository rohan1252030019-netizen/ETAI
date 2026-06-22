"""
IMMUNEX SOC Copilot Engine — Phase 9 Upgrade
=============================================
Wraps and extends the existing ``soc_copilot.EnterpriseSOCCopilot`` with
structured Pydantic query/response models and integration points for every
Phase 7-8 engine:

  - AttackGraphEngine   (core.attack_graph_engine)
  - CVEPrioritizationEngine (core.cve_prioritization)
  - IndustrialTwinSimulator (core.digital_twin_simulator)
  - ExecutiveImpactEngine   (core.business_impact)
  - MultiAgentOrchestrator  (agents.orchestrator)
  - SOAROrchestrator        (soc.soar_orchestrator)
  - AdvisoryIngestionPipeline (telemetry.advisory_ingestion)

Air-gapped & CPU-only compatible.  Every import is lazily guarded so the
module remains importable even when upstream dependencies have not been
deployed yet.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from utils.logger import log

# ─── Pydantic Models ─────────────────────────────────────────────────────────


class QueryType(str, Enum):
    """Supported copilot query intents."""

    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    ATTACK_PATH = "ATTACK_PATH"
    ALERT_EXPLANATION = "ALERT_EXPLANATION"
    MITRE_LOOKUP = "MITRE_LOOKUP"
    PLAYBOOK_RECOMMENDATION = "PLAYBOOK_RECOMMENDATION"
    GENERAL = "GENERAL"


class CopilotQuery(BaseModel):
    """Inbound query sent to the copilot."""

    query_text: str = Field(..., min_length=1, description="Natural-language or structured query text")
    query_type: QueryType = Field(default=QueryType.GENERAL, description="Explicit intent enum")
    context: Dict[str, Any] = Field(default_factory=dict, description="Optional key-value context bag")


class CopilotResponse(BaseModel):
    """Structured copilot response returned from every handler."""

    response_text: str = Field(..., description="Human-readable response")
    structured_data: Dict[str, Any] = Field(default_factory=dict, description="Machine-readable payload")
    visualizations: List[Dict[str, Any]] = Field(default_factory=list, description="Vis descriptors for the frontend")
    actions_available: List[str] = Field(default_factory=list, description="Follow-up actions the user can take")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence 0-1")
    processing_time_ms: float = Field(default=0.0, ge=0.0, description="Wall-clock ms spent")


# ─── Lazy Engine Loader Helpers ──────────────────────────────────────────────


def _try_import(label: str, factory):
    """Execute *factory* and return the instance, or ``None`` on failure."""
    try:
        return factory()
    except Exception as exc:  # noqa: BLE001
        log.info(f"CopilotEngine: {label} unavailable — {exc}")
        return None


# ─── Intent Detection Patterns (mirrored from NaturalLanguageThreatHunter) ───

_INTENT_PATTERNS: dict[str, QueryType] = {}

_RISK_KW = [
    "risk", "cve", "vulnerability", "vulnerabilities", "exposure",
    "prioritize", "prioritise", "asset risk", "patch",
]
_PATH_KW = [
    "attack path", "lateral", "shortest path", "blast radius",
    "graph", "topology", "reachable",
]
_ALERT_KW = [
    "explain alert", "alert", "investigate", "what happened",
    "root cause", "analyze alert", "analyse alert",
]
_MITRE_KW = [
    "mitre", "att&ck", "tactic", "technique", "T1", "TA0",
    "kill chain", "attack stage",
]
_PLAYBOOK_KW = [
    "playbook", "soar", "respond", "remediate", "containment",
    "runbook", "automate response", "isolate",
]

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _detect_intent(text: str) -> QueryType:
    """Keyword-based intent classification."""
    lower = text.lower()
    for kw in _PATH_KW:
        if kw in lower:
            return QueryType.ATTACK_PATH
    for kw in _RISK_KW:
        if kw in lower:
            return QueryType.RISK_ASSESSMENT
    for kw in _ALERT_KW:
        if kw in lower:
            return QueryType.ALERT_EXPLANATION
    for kw in _MITRE_KW:
        if kw in lower:
            return QueryType.MITRE_LOOKUP
    for kw in _PLAYBOOK_KW:
        if kw in lower:
            return QueryType.PLAYBOOK_RECOMMENDATION
    return QueryType.GENERAL


# ─── CopilotEngine ───────────────────────────────────────────────────────────


class CopilotEngine:
    """
    Phase 9 SOC Copilot engine.

    Wraps the existing ``EnterpriseSOCCopilot`` and adds structured
    integrations with all Phase 7-8 engines, exposing every method as a
    ``CopilotResponse`` with timing, confidence, and available actions.
    """

    def __init__(self) -> None:
        log.info("CopilotEngine: initialising…")

        # ── Legacy copilot ────────────────────────────────────────────────
        self._legacy_copilot = _try_import(
            "EnterpriseSOCCopilot",
            lambda: __import__("soc_copilot", fromlist=["EnterpriseSOCCopilot"]).EnterpriseSOCCopilot(),
        )

        # ── NL threat hunter (always available) ───────────────────────────
        self._nl_hunter = _try_import(
            "NaturalLanguageThreatHunter",
            lambda: __import__("soc_copilot", fromlist=["NaturalLanguageThreatHunter"]).NaturalLanguageThreatHunter(),
        )

        # ── Phase 7-8 engines (all optional) ──────────────────────────────
        self._attack_graph = _try_import(
            "AttackGraphEngine",
            lambda: __import__("core.attack_graph_engine", fromlist=["AttackGraphEngine"]).AttackGraphEngine(bootstrap=True),
        )

        self._cve_engine = _try_import(
            "CVEPrioritizationEngine",
            lambda: __import__("core.cve_prioritization", fromlist=["CVEPrioritizationEngine"]).CVEPrioritizationEngine(),
        )

        self._twin_sim = _try_import(
            "IndustrialTwinSimulator",
            lambda: __import__("core.digital_twin_simulator", fromlist=["IndustrialTwinSimulator"]).IndustrialTwinSimulator(),
        )

        self._biz_impact = _try_import(
            "ExecutiveImpactEngine",
            lambda: __import__("core.business_impact", fromlist=["ExecutiveImpactEngine"]).ExecutiveImpactEngine(),
        )

        self._orchestrator = _try_import(
            "MultiAgentOrchestrator",
            lambda: __import__("agents.orchestrator", fromlist=["MultiAgentOrchestrator"]).MultiAgentOrchestrator(),
        )

        self._soar = _try_import(
            "SOAROrchestrator",
            lambda: __import__("soc.soar_orchestrator", fromlist=["SOAROrchestrator"]).SOAROrchestrator(),
        )

        self._advisory_pipeline = _try_import(
            "AdvisoryIngestionPipeline",
            lambda: __import__("telemetry.advisory_ingestion", fromlist=["AdvisoryIngestionPipeline"]).AdvisoryIngestionPipeline(),
        )

        # MITRE explainer (may already live in legacy copilot)
        self._mitre_explainer = _try_import(
            "MITREExplainer",
            lambda: __import__("mitre_explainer", fromlist=["MITREExplainer"]).MITREExplainer(),
        )

        log.info(
            "CopilotEngine: ready",
            legacy=self._legacy_copilot is not None,
            attack_graph=self._attack_graph is not None,
            cve=self._cve_engine is not None,
            twin=self._twin_sim is not None,
            biz_impact=self._biz_impact is not None,
            soar=self._soar is not None,
            orchestrator=self._orchestrator is not None,
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _timed(func):
        """Decorator-style helper that returns result + elapsed ms."""
        start = time.perf_counter()
        result = func()
        elapsed = (time.perf_counter() - start) * 1000.0
        return result, elapsed

    def _engine_names(self) -> list[str]:
        """Return names of available engines (used in GENERAL responses)."""
        engines: list[str] = []
        if self._legacy_copilot:
            engines.append("LegacySOCCopilot")
        if self._attack_graph:
            engines.append("AttackGraphEngine")
        if self._cve_engine:
            engines.append("CVEPrioritizationEngine")
        if self._twin_sim:
            engines.append("IndustrialTwinSimulator")
        if self._biz_impact:
            engines.append("ExecutiveImpactEngine")
        if self._soar:
            engines.append("SOAROrchestrator")
        if self._orchestrator:
            engines.append("MultiAgentOrchestrator")
        if self._mitre_explainer:
            engines.append("MITREExplainer")
        if self._advisory_pipeline:
            engines.append("AdvisoryIngestionPipeline")
        return engines

    # ── Public API Methods ────────────────────────────────────────────────

    def assess_risk(self, asset_ip: str) -> CopilotResponse:
        """Assess risk for *asset_ip* using CVE engine + attack graph."""
        start = time.perf_counter()

        vulnerabilities: list[dict] = []
        risk_score: float = 0.0
        attack_paths: list[dict] = []

        # CVE engine — asset assessment
        if self._cve_engine:
            try:
                assessment = self._cve_engine.assess_asset(asset_ip)
                if isinstance(assessment, dict):
                    vulnerabilities = assessment.get("vulnerabilities", [])
                    risk_score = assessment.get("risk_score", 0.0)
                elif isinstance(assessment, list):
                    vulnerabilities = assessment
                    risk_score = max((v.get("risk_score", 0) for v in vulnerabilities), default=0.0)
            except Exception as exc:
                log.warning("CopilotEngine.assess_risk: CVE engine error", error=str(exc))

        # Attack graph — reachability
        if self._attack_graph:
            try:
                paths = self._attack_graph.find_shortest_path(asset_ip, "crown_jewel")
                if paths:
                    attack_paths = paths if isinstance(paths, list) else [paths]
            except Exception as exc:
                log.debug("CopilotEngine.assess_risk: attack graph error", error=str(exc))

        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text=(
                f"Risk assessment for {asset_ip}: score={risk_score:.2f}, "
                f"{len(vulnerabilities)} vulnerabilities, {len(attack_paths)} attack paths."
            ),
            structured_data={
                "asset_ip": asset_ip,
                "risk_score": risk_score,
                "vulnerabilities": vulnerabilities,
                "attack_paths": attack_paths,
            },
            visualizations=[{"type": "risk_gauge", "value": risk_score}],
            actions_available=["show_attack_path", "recommend_playbook", "get_executive_summary"],
            confidence=min(1.0, 0.5 + (0.25 if self._cve_engine else 0) + (0.25 if self._attack_graph else 0)),
            processing_time_ms=elapsed,
        )

    def show_attack_path(self, source: str, target: str) -> CopilotResponse:
        """Compute and return shortest attack path between *source* and *target*."""
        start = time.perf_counter()

        path_data: dict[str, Any] = {"source": source, "target": target, "paths": [], "blast_radius": {}}

        if self._attack_graph:
            try:
                path_result = self._attack_graph.find_shortest_path(source, target)
                path_data["paths"] = path_result if isinstance(path_result, list) else [path_result] if path_result else []
            except Exception as exc:
                log.warning("show_attack_path: path lookup failed", error=str(exc))

            try:
                blast = self._attack_graph.blast_radius(source)
                path_data["blast_radius"] = blast if isinstance(blast, dict) else {"affected_nodes": blast}
            except Exception as exc:
                log.debug("show_attack_path: blast radius failed", error=str(exc))
        else:
            # Heuristic fallback
            path_data["paths"] = [f"{source} → internal_switch → {target}"]
            path_data["blast_radius"] = {"affected_nodes": 3, "engine": "heuristic"}

        elapsed = (time.perf_counter() - start) * 1000.0
        num_paths = len(path_data["paths"])

        return CopilotResponse(
            response_text=f"Found {num_paths} attack path(s) from {source} → {target}.",
            structured_data=path_data,
            visualizations=[{"type": "network_graph", "source": source, "target": target}],
            actions_available=["assess_risk", "recommend_playbook"],
            confidence=0.85 if self._attack_graph else 0.3,
            processing_time_ms=elapsed,
        )

    def explain_alert(self, alert_id: str, alert_data: Optional[dict] = None) -> CopilotResponse:
        """Explain an alert using MITRE mapping + RAG context retrieval."""
        start = time.perf_counter()
        alert_data = alert_data or {}

        explanation: dict[str, Any] = {"alert_id": alert_id, "mitre_mapping": {}, "context": {}, "narrative": ""}

        # MITRE mapping
        event_type = alert_data.get("event_type", "unknown")
        if self._mitre_explainer:
            try:
                techniques = self._mitre_explainer.map_event_type_to_techniques(event_type)
                explanation["mitre_mapping"] = {"event_type": event_type, "techniques": techniques}
            except Exception:
                try:
                    # Fallback: use the full matrix lookup
                    matrix = self._mitre_explainer.get_full_matrix()
                    explanation["mitre_mapping"] = {"matrix_tactics": len(matrix)}
                except Exception:
                    pass

        # RAG context
        if self._legacy_copilot:
            try:
                ctx = self._legacy_copilot.explain_incident(alert_id)
                explanation["context"] = ctx
                explanation["narrative"] = ctx.get("narrative", "")
            except Exception:
                pass

        # Investigation enrichment
        if self._legacy_copilot:
            try:
                inv = self._legacy_copilot.investigate(alert_id)
                explanation["investigation"] = inv
            except Exception:
                pass

        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text=f"Alert {alert_id} explained. {explanation.get('narrative', '')}",
            structured_data=explanation,
            actions_available=["recommend_playbook", "show_attack_path", "assess_risk"],
            confidence=0.7 if self._mitre_explainer else 0.35,
            processing_time_ms=elapsed,
        )

    def list_mitre_techniques(self, event_type: str) -> CopilotResponse:
        """List MITRE ATT&CK techniques relevant to *event_type*."""
        start = time.perf_counter()

        techniques: list[dict] = []

        if self._mitre_explainer:
            try:
                # Try the per-event-type mapper
                result = self._mitre_explainer.map_event_type_to_techniques(event_type)
                techniques = result if isinstance(result, list) else [result]
            except Exception:
                try:
                    matrix = self._mitre_explainer.get_full_matrix()
                    techniques = [{"tactic": t} for t in matrix] if isinstance(matrix, dict) else matrix
                except Exception:
                    pass

        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text=f"Found {len(techniques)} MITRE techniques for event type '{event_type}'.",
            structured_data={"event_type": event_type, "techniques": techniques},
            visualizations=[{"type": "mitre_heatmap", "event_type": event_type}],
            actions_available=["explain_alert", "recommend_playbook"],
            confidence=0.9 if techniques else 0.2,
            processing_time_ms=elapsed,
        )

    def recommend_playbook(self, threat_type: str, severity: str = "HIGH") -> CopilotResponse:
        """Recommend a SOAR playbook for the given threat type and severity."""
        start = time.perf_counter()

        playbook: dict[str, Any] = {}

        if self._soar:
            try:
                match = self._soar.match_playbook(threat_type)
                if match:
                    playbook = match if isinstance(match, dict) else {"playbook": match}
            except Exception as exc:
                log.debug("recommend_playbook: SOAR match failed", error=str(exc))

        # Fallback: built-in heuristic playbooks
        if not playbook:
            playbook = self._builtin_playbook(threat_type, severity)

        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text=f"Recommended playbook for '{threat_type}' (severity={severity}).",
            structured_data={"threat_type": threat_type, "severity": severity, "playbook": playbook},
            actions_available=["execute_playbook", "assess_risk"],
            confidence=0.8 if self._soar else 0.5,
            processing_time_ms=elapsed,
        )

    def query_threat_intel(self, query: str) -> CopilotResponse:
        """Query RAG-backed advisory search / threat intelligence."""
        start = time.perf_counter()

        results: list[dict] = []

        # Advisory pipeline
        if self._advisory_pipeline:
            try:
                results = self._advisory_pipeline.search(query)
                if not isinstance(results, list):
                    results = [results]
            except Exception:
                pass

        # Fallback: legacy copilot hunt
        if not results and self._legacy_copilot:
            try:
                hunt_result = self._legacy_copilot.hunt(query)
                results = hunt_result.get("results", [])
            except Exception:
                pass

        # NL hunter parse for structured info
        parsed: dict = {}
        if self._nl_hunter:
            try:
                parsed = self._nl_hunter.parse_query(query)
            except Exception:
                pass

        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text=f"Threat intel query returned {len(results)} result(s).",
            structured_data={"query": query, "parsed": parsed, "results": results},
            actions_available=["assess_risk", "explain_alert", "recommend_playbook"],
            confidence=0.7 if results else 0.2,
            processing_time_ms=elapsed,
        )

    def get_executive_summary(self) -> CopilotResponse:
        """Generate an executive-level impact summary."""
        start = time.perf_counter()

        summary: dict[str, Any] = {}

        if self._biz_impact:
            try:
                result = self._biz_impact.generate_summary()
                summary = result if isinstance(result, dict) else {"summary": str(result)}
            except Exception as exc:
                log.debug("get_executive_summary: biz impact error", error=str(exc))

        # Enrich with system stats
        if self._legacy_copilot:
            try:
                stats = self._legacy_copilot._get_stats()
                summary["system_stats"] = stats
            except Exception:
                pass

        # Enrich with twin sim overview
        if self._twin_sim:
            try:
                overview = self._twin_sim.topology_summary()
                summary["topology_overview"] = overview if isinstance(overview, dict) else {"raw": overview}
            except Exception:
                pass

        if not summary:
            summary = {
                "status": "operational",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "engines_available": self._engine_names(),
                "risk_posture": "nominal",
            }

        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text="Executive summary generated.",
            structured_data=summary,
            visualizations=[{"type": "executive_dashboard"}],
            actions_available=["assess_risk", "show_attack_path", "query_threat_intel"],
            confidence=0.75 if self._biz_impact else 0.4,
            processing_time_ms=elapsed,
        )

    def process_natural_language(self, query: str) -> CopilotResponse:
        """
        NL router: detect intent from free-text and dispatch to the
        appropriate structured method.
        """
        start = time.perf_counter()

        intent = _detect_intent(query)
        log.debug("CopilotEngine NL router", query=query[:80], intent=intent.value)

        # Extract IPs from the query for methods that need them
        ips = _IP_PATTERN.findall(query)

        if intent == QueryType.RISK_ASSESSMENT:
            target_ip = ips[0] if ips else "0.0.0.0"
            return self.assess_risk(target_ip)

        if intent == QueryType.ATTACK_PATH:
            source = ips[0] if len(ips) >= 1 else "attacker"
            target = ips[1] if len(ips) >= 2 else "crown_jewel"
            return self.show_attack_path(source, target)

        if intent == QueryType.ALERT_EXPLANATION:
            # Try to extract an alert/event ID
            id_match = re.search(r"([A-Za-z0-9\-_]{8,})", query)
            alert_id = id_match.group(1) if id_match else "unknown"
            return self.explain_alert(alert_id, {"raw_query": query})

        if intent == QueryType.MITRE_LOOKUP:
            # Extract technique / tactic ID or use the event-type keywords
            technique_match = re.search(r"(T\d{4}(?:\.\d{3})?)", query, re.IGNORECASE)
            event_type = technique_match.group(1) if technique_match else "general"
            return self.list_mitre_techniques(event_type)

        if intent == QueryType.PLAYBOOK_RECOMMENDATION:
            # Attempt to extract a threat type keyword
            threat_type = "general"
            for kw in ["ransomware", "phishing", "lateral", "brute", "exfiltration",
                        "c2", "privilege", "malware", "insider"]:
                if kw in query.lower():
                    threat_type = kw
                    break
            return self.recommend_playbook(threat_type)

        # ── GENERAL fallback ──────────────────────────────────────────────
        elapsed = (time.perf_counter() - start) * 1000.0

        return CopilotResponse(
            response_text=(
                "I'm the IMMUNEX SOC Copilot (Phase 9). I can help you with:\n"
                "• **Risk Assessment** — assess_risk(asset_ip)\n"
                "• **Attack Paths** — show_attack_path(source, target)\n"
                "• **Alert Explanation** — explain_alert(alert_id)\n"
                "• **MITRE Lookup** — list_mitre_techniques(event_type)\n"
                "• **Playbook Recommendation** — recommend_playbook(threat_type)\n"
                "• **Threat Intel** — query_threat_intel(query)\n"
                "• **Executive Summary** — get_executive_summary()\n"
            ),
            structured_data={"engines_available": self._engine_names(), "detected_intent": intent.value},
            actions_available=[
                "assess_risk", "show_attack_path", "explain_alert",
                "list_mitre_techniques", "recommend_playbook",
                "query_threat_intel", "get_executive_summary",
            ],
            confidence=0.5,
            processing_time_ms=elapsed,
        )

    # ── Private Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _builtin_playbook(threat_type: str, severity: str) -> dict:
        """Heuristic playbook when SOAR is unavailable."""
        playbooks: dict[str, dict] = {
            "ransomware": {
                "name": "Ransomware Containment",
                "steps": [
                    "Isolate affected hosts from network",
                    "Block C2 domains at DNS/proxy",
                    "Disable affected user accounts",
                    "Snapshot affected volumes for forensics",
                    "Deploy decryption tool if available",
                ],
                "severity": "CRITICAL",
            },
            "phishing": {
                "name": "Phishing Response",
                "steps": [
                    "Quarantine reported email",
                    "Search for similar emails across mailboxes",
                    "Block sender domain",
                    "Reset credentials for affected users",
                    "Scan attachments in sandbox",
                ],
                "severity": "HIGH",
            },
            "lateral": {
                "name": "Lateral Movement Response",
                "steps": [
                    "Restrict inter-subnet traffic",
                    "Force re-authentication for affected sessions",
                    "Enable enhanced logging on pivot hosts",
                    "Deploy honeytokens on adjacent segments",
                ],
                "severity": "HIGH",
            },
            "brute": {
                "name": "Brute-Force Mitigation",
                "steps": [
                    "Block source IP at firewall",
                    "Enable account lockout policies",
                    "Force password reset for targeted accounts",
                    "Review MFA enrollment status",
                ],
                "severity": "MEDIUM",
            },
            "exfiltration": {
                "name": "Data Exfiltration Response",
                "steps": [
                    "Block destination IP/domain",
                    "Terminate suspicious process",
                    "Audit accessed files and data classification",
                    "Notify data protection officer",
                ],
                "severity": "CRITICAL",
            },
        }

        pb = playbooks.get(threat_type, {
            "name": f"General Response — {threat_type}",
            "steps": [
                "Investigate alert context",
                "Assess blast radius",
                "Apply containment measures",
                "Collect forensic evidence",
                "Notify SOC team lead",
            ],
            "severity": severity,
        })
        pb["engine"] = "builtin_heuristic"
        return pb
