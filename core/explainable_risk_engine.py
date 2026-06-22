"""
Explainable Risk Engine

Generates traceable evidence chains for every risk prediction.

Provides:
    - Which factors influenced the score
    - Supporting evidence with confidence
    - Alternative scenarios
    - Limitations and caveats

Author: IMMUNEX Core Team
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass

logger , timezone= logging.getLogger(__name__)


@dataclass
class EvidenceChain:
    """Traceable evidence for a prediction."""
    prediction_id: str
    primary_score: float
    component_scores: Dict[str, float]
    evidence_factors: List[Dict[str, Any]]  # [{factor, value, weight, confidence}]
    confidence_interval: Tuple[float, float]
    alternative_scenarios: List[Dict[str, Any]]
    limitations: List[str]
    generated_at: datetime


class ExplainableRiskEngine:
    """
    Generates explainable evidence chains for risk predictions.
    
    For every risk score, explains:
        1. Which components contributed most
        2. Which CVEs influenced the decision
        3. Which MITRE techniques were detected
        4. Which threat actor patterns matched
        5. Confidence intervals
        6. Alternative scenarios
        7. Known limitations
    """
    
    def __init__(self, risk_models, graph_engine, cve_db, mitre_mapper, 
                 threat_actor_db):
        """
        Initialize explainability engine.
        
        Args:
            risk_models: Risk calculation modules
            graph_engine: Attack graph for path explanation
            cve_db: CVE database for vulnerability details
            mitre_mapper: MITRE ATT&CK mapping
            threat_actor_db: Threat actor profiles
        """
        self.risk_models = risk_models
        self.graph = graph_engine
        self.cves = cve_db
        self.mitre = mitre_mapper
        self.threat_actors = threat_actor_db
    
    def explain_asset_risk(self, asset_ip: str) -> EvidenceChain:
        """
        Generate full explainability report for asset risk score.
        
        Returns:
            EvidenceChain with evidence factors, confidence, caveats
        """
        # Get risk score components
        vuln_score = self._calculate_vulnerability_score(asset_ip)
        exposure_score = self._calculate_exposure_score(asset_ip)
        incident_score = self._calculate_incident_history_score(asset_ip)
        threat_score = self._calculate_threat_likelihood_score(asset_ip)
        
        component_scores = {
            'vulnerability': vuln_score,
            'exposure': exposure_score,
            'incident_history': incident_score,
            'threat_likelihood': threat_score
        }
        
        # Weighted combination
        primary_score = (
            0.35 * vuln_score +
            0.25 * exposure_score +
            0.20 * incident_score +
            0.20 * threat_score
        )
        
        # Gather evidence
        evidence_factors = self._gather_evidence_factors(asset_ip)
        
        # Compute confidence interval
        ci_lower, ci_upper = self._compute_confidence_interval(asset_ip)
        
        # Generate alternative scenarios
        alternatives = self._generate_alternative_scenarios(asset_ip, primary_score)
        
        # Identify limitations
        limitations = self._identify_limitations(asset_ip)
        
        return EvidenceChain(
            prediction_id=f"risk_{asset_ip}_{datetime.now(timezone.utc).isoformat()}",
            primary_score=primary_score,
            component_scores=component_scores,
            evidence_factors=evidence_factors,
            confidence_interval=(ci_lower, ci_upper),
            alternative_scenarios=alternatives,
            limitations=limitations,
            generated_at=datetime.now(timezone.utc)
        )
    
    def _gather_evidence_factors(self, asset_ip: str) -> List[Dict[str, Any]]:
        """Gather all evidence factors supporting the risk score."""
        factors = []
        
        # Vulnerability evidence
        critical_vulns = self.cves.count_critical_for_asset(asset_ip)
        if critical_vulns > 0:
            factors.append({
                'factor': 'Critical Vulnerabilities',
                'value': critical_vulns,
                'weight': 0.15,
                'confidence': 0.95,
                'cves': self.cves.get_critical_cve_ids(asset_ip)[:3]
            })
        
        # Exposure evidence
        if self._is_internet_exposed(asset_ip):
            factors.append({
                'factor': 'Internet Exposed',
                'value': True,
                'weight': 0.12,
                'confidence': 0.99,
                'details': 'Asset reachable from Internet'
            })
        
        # Incident history evidence
        recent_incidents = self._get_recent_incidents(asset_ip, days=90)
        if recent_incidents > 0:
            factors.append({
                'factor': 'Recent Incidents',
                'value': recent_incidents,
                'weight': 0.10,
                'confidence': 0.90,
                'details': f'{recent_incidents} incidents in last 90 days'
            })
        
        # Threat actor evidence
        threat_actors = self._get_matching_threat_actors(asset_ip)
        if threat_actors:
            factors.append({
                'factor': 'Matching Threat Actors',
                'value': len(threat_actors),
                'weight': 0.08,
                'confidence': 0.75,
                'actors': threat_actors
            })
        
        # Attack path evidence
        hops_to_critical = self.graph.min_hops_to_critical_asset(asset_ip)
        if hops_to_critical < 5:
            factors.append({
                'factor': 'Attack Path to Critical Asset',
                'value': hops_to_critical,
                'weight': 0.07,
                'confidence': 0.85,
                'details': f'Only {hops_to_critical} hops to critical system'
            })
        
        return sorted(factors, key=lambda x: x['weight'], reverse=True)
    
    def _compute_confidence_interval(self, asset_ip: str) -> Tuple[float, float]:
        """
        Compute 95% confidence interval via bootstrap resampling.
        
        Returns:
            (lower_bound, upper_bound)
        """
        # Placeholder: would do bootstrap sampling
        return (0.35, 0.65)
    
    def _generate_alternative_scenarios(self, asset_ip: str, 
                                       primary_score: float) -> List[Dict]:
        """
        Generate alternative risk scenarios.
        
        Returns:
            List of alternative interpretations
        """
        return [
            {
                'scenario': 'If critical vulnerabilities are patched',
                'adjusted_score': primary_score * 0.5,
                'probability': 0.3,
                'description': 'Risk would decrease by 50%'
            },
            {
                'scenario': 'If recent incidents were due to misconfiguration',
                'adjusted_score': primary_score * 0.8,
                'probability': 0.2,
                'description': 'Risk would decrease by 20%'
            }
        ]
    
    def _identify_limitations(self, asset_ip: str) -> List[str]:
        """Identify and surface model limitations and caveats."""
        limitations = []
        
        # Data completeness
        if not self._has_complete_asset_inventory(asset_ip):
            limitations.append('Asset inventory incomplete - risk may be underestimated')
        
        # Model applicability
        if self._is_isolated_system(asset_ip):
            limitations.append('Isolated systems may have different risk profile')
        
        # Data freshness
        if self._data_is_stale(asset_ip):
            limitations.append('Risk data > 7 days old - may not reflect current state')
        
        # Model assumptions
        limitations.append('Model assumes threat actors follow known patterns')
        limitations.append('Zero-day vulnerabilities not accounted for')
        
        return limitations
    
    def explain_forecast(self, asset_ip: str, forecast_score: float) -> EvidenceChain:
        """Explain forecast prediction for an asset."""
        # Similar structure to explain_asset_risk but focused on forecast factors
        evidence_factors = [
            {
                'factor': 'Historical Attack Frequency',
                'value': 0.45,
                'weight': 0.35,
                'confidence': 0.82
            },
            {
                'factor': 'Lateral Movement Capability',
                'value': 0.60,
                'weight': 0.25,
                'confidence': 0.78
            }
        ]
        
        return EvidenceChain(
            prediction_id=f"forecast_{asset_ip}",
            primary_score=forecast_score,
            component_scores={},
            evidence_factors=evidence_factors,
            confidence_interval=(forecast_score - 0.15, forecast_score + 0.15),
            alternative_scenarios=[],
            limitations=['Forecast assumes threat landscape remains stable'],
            generated_at=datetime.now(timezone.utc)
        )
    
    # Placeholder helper methods
    def _calculate_vulnerability_score(self, asset_ip: str) -> float:
        return 0.6
    
    def _calculate_exposure_score(self, asset_ip: str) -> float:
        return 0.7
    
    def _calculate_incident_history_score(self, asset_ip: str) -> float:
        return 0.4
    
    def _calculate_threat_likelihood_score(self, asset_ip: str) -> float:
        return 0.5
    
    def _is_internet_exposed(self, asset_ip: str) -> bool:
        return False
    
    def _get_recent_incidents(self, asset_ip: str, days: int) -> int:
        return 0
    
    def _get_matching_threat_actors(self, asset_ip: str) -> List[str]:
        return []
    
    def _has_complete_asset_inventory(self, asset_ip: str) -> bool:
        return True
    
    def _is_isolated_system(self, asset_ip: str) -> bool:
        return False
    
    def _data_is_stale(self, asset_ip: str) -> bool:
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Explainable Risk Engine loaded")
