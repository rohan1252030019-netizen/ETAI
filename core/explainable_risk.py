"""
CNI-Resilience Explainable AI (XAI) Risk Engine
================================================
Compiles evidence graphs, decision traces, and structured justifications
for risk predictions, lateral path forecasts, and threat attributions.
"""

from __future__ import annotations
from typing import Any, Dict, List
import time
from pydantic import BaseModel, Field

class DecisionTrace(BaseModel):
    prediction_id: str
    target_ip: str
    target_hostname: str = ""
    composite_risk_score: float
    confidence_score: float
    primary_threat_actor: str = "Unknown"
    reasons: List[str] = Field(default_factory=list)
    evidence_metrics: Dict[str, Any] = Field(default_factory=dict)
    contributing_cves: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    influencing_graph_path: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)

class ExplainableRiskEngine:
    def __init__(self) -> None:
        pass

    def generate_decision_trace(
        self,
        target_ip: str,
        hostname: str,
        risk_score: float,
        graph_path: List[str],
        vulnerabilities: List[Dict[str, Any]],
        mitre_mappings: List[str],
        attribution: Dict[str, Any] | None = None
    ) -> DecisionTrace:
        """
        Synthesizes raw threat metrics, path traversals, CVE metrics, and actor attributions
        into an explainable decision trace with confidence bounds.
        """
        reasons = []
        contributing_cves = []
        confidence_factors = []
        
        # 1. Evaluate Vulnerabilities
        high_cvss_count = 0
        in_kev_count = 0
        for v in vulnerabilities:
            cve_id = v.get("cve_id", "Unknown-CVE")
            contributing_cves.append(cve_id)
            
            cvss = v.get("cvss_score", 0.0)
            if cvss >= 8.5:
                high_cvss_count += 1
            if v.get("in_kev", False):
                in_kev_count += 1

        if high_cvss_count > 0:
            reasons.append(f"Identified {high_cvss_count} vulnerabilities with critical CVSS scores (>= 8.5)")
        if in_kev_count > 0:
            reasons.append(f"Contains {in_kev_count} vulnerabilities active in CISA Known Exploited Vulnerabilities (KEV)")
            confidence_factors.append(0.95)
        else:
            confidence_factors.append(0.70)

        # 2. Evaluate Graph Path Accessibility
        path_length = len(graph_path)
        if path_length > 1:
            reasons.append(f"Target is reachable via {path_length - 1} lateral movement hops from entry point")
            # Shorter path means higher compromise certainty
            path_confidence = max(1.0 - (path_length * 0.1), 0.5)
            confidence_factors.append(path_confidence)
        else:
            reasons.append("Asset is isolated or has no known direct lateral path from external zones")
            confidence_factors.append(0.50)

        # 3. Evaluate MITRE & Attribution
        actor_name = "Unknown"
        if attribution:
            actor_name = attribution.get("actor_name", "Unknown")
            match_count = attribution.get("matched_count", 0)
            base_conf = attribution.get("base_confidence", 0.5)
            reasons.append(f"TTP alignment suggests activity profile of Threat Actor '{actor_name}' (matched TTP count: {match_count})")
            confidence_factors.append(base_conf)
        else:
            confidence_factors.append(0.60)

        # Calculate average confidence
        overall_confidence = sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.70

        # Construct evidence details
        evidence = {
            "critical_cves_count": high_cvss_count,
            "cisa_kev_match": in_kev_count > 0,
            "path_hops": path_length - 1 if path_length > 1 else 0,
            "mitre_ttps_mapped": len(mitre_mappings),
            "threat_actor_correlation_score": attribution.get("base_confidence", 0.0) if attribution else 0.0
        }

        # Generate unique prediction ID
        import uuid
        pred_id = f"XAI-TRACE-{uuid.uuid4().hex[:8].upper()}"

        return DecisionTrace(
            prediction_id=pred_id,
            target_ip=target_ip,
            target_hostname=hostname,
            composite_risk_score=round(risk_score, 2),
            confidence_score=round(overall_confidence, 2),
            primary_threat_actor=actor_name,
            reasons=reasons,
            evidence_metrics=evidence,
            contributing_cves=contributing_cves,
            mitre_techniques=mitre_mappings,
            influencing_graph_path=graph_path
        )
