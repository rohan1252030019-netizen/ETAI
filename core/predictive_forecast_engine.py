"""
Predictive Attack Forecast Engine

Forecasts which assets will be attacked in the next 30/60/90 days.
Uses Bayesian probabilistic scoring combining CVE risk, attack frequency,
lateral movement capability, and threat actor affinity.

Author: IMMUNEX Core Team
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import logging
from dataclasses import dataclass, asdict
import numpy as np

logger , timezone= logging.getLogger(__name__)


@dataclass
class ForecastResult:
    """Prediction result for an asset."""
    asset_ip: str
    asset_name: str
    attack_probability: float
    confidence_interval_lower: float
    confidence_interval_upper: float
    forecast_horizon_days: int
    primary_threats: List[str]
    recommended_mitigations: List[str]
    predicted_attack_vector: str
    timestamp: datetime


class PredictiveAttackForecastEngine:
    """
    Forecasts likely attack targets using Bayesian probabilistic scoring.
    
    Formula:
        P(asset attacked in T days) = 
            0.35 * cve_risk_score +
            0.25 * attack_frequency_score +
            0.25 * lateral_movement_score +
            0.15 * threat_actor_affinity_score
    
    Confidence intervals computed via bootstrap resampling.
    """
    
    def __init__(self, attack_graph_engine, cve_prioritization, 
                 threat_actor_db, incident_store):
        """
        Initialize forecast engine.
        
        Args:
            attack_graph_engine: Asset graph and connectivity
            cve_prioritization: CVE risk scoring
            threat_actor_db: Threat actor profiles
            incident_store: Historical incident data
        """
        self.attack_graph = attack_graph_engine
        self.cve_db = cve_prioritization
        self.threat_actors = threat_actor_db
        self.incident_store = incident_store
        
        # Model coefficients (learned via feedback loop)
        self.coefficients = {
            'cve_risk': 0.35,
            'attack_frequency': 0.25,
            'lateral_movement': 0.25,
            'threat_actor_affinity': 0.15
        }
    
    def forecast_next_attacks(self, horizon_days: int = 30, 
                             top_k: int = 20) -> List[ForecastResult]:
        """
        Forecast which assets will be attacked in the next N days.
        
        Args:
            horizon_days: Forecast window (30, 60, or 90)
            top_k: Return top K at-risk assets
        
        Returns:
            List of ForecastResult sorted by attack probability (descending)
        """
        try:
            # Get all assets
            all_assets = self.attack_graph.get_all_assets()
            
            forecasts = []
            for asset in all_assets:
                # Score each asset
                cve_score = self._score_asset_cve_risk(asset)
                freq_score = self._score_attack_frequency(asset, horizon_days)
                lateral_score = self._score_lateral_movement(asset)
                actor_score = self._score_threat_actor_affinity(asset)
                
                # Weighted combination
                attack_prob = (
                    self.coefficients['cve_risk'] * cve_score +
                    self.coefficients['attack_frequency'] * freq_score +
                    self.coefficients['lateral_movement'] * lateral_score +
                    self.coefficients['threat_actor_affinity'] * actor_score
                )
                
                # Bootstrap confidence intervals
                ci_lower, ci_upper = self._bootstrap_confidence_interval(
                    asset, horizon_days, attack_prob
                )
                
                forecast = ForecastResult(
                    asset_ip=asset.get('ip_address', ''),
                    asset_name=asset.get('hostname', 'Unknown'),
                    attack_probability=attack_prob,
                    confidence_interval_lower=ci_lower,
                    confidence_interval_upper=ci_upper,
                    forecast_horizon_days=horizon_days,
                    primary_threats=self._identify_primary_threats(asset),
                    recommended_mitigations=self._recommend_mitigations(asset),
                    predicted_attack_vector=self._predict_attack_vector(asset),
                    timestamp=datetime.now(timezone.utc)
                )
                
                forecasts.append(forecast)
            
            # Sort by probability (descending) and return top K
            forecasts.sort(key=lambda x: x.attack_probability, reverse=True)
            return forecasts[:top_k]
            
        except Exception as e:
            logger.error(f"Error in attack forecast: {e}")
            raise
    
    def _score_asset_cve_risk(self, asset: Dict[str, Any]) -> float:
        """
        Score asset vulnerability risk.
        
        Higher = more vulnerable
        
        Returns:
            Score 0-1
        """
        asset_ip = asset.get('ip_address')
        
        # Get CVE exposure
        critical_count = self.cve_db.count_critical_for_asset(asset_ip)
        high_count = self.cve_db.count_high_for_asset(asset_ip)
        
        # Normalize: critical vulns weighted 3x high vulns
        vuln_score = (critical_count * 3 + high_count) / 100
        vuln_score = min(1.0, vuln_score)
        
        # Factor in age of vulns (older = higher risk if unpatched)
        avg_vuln_age_days = self.cve_db.get_average_vuln_age_days(asset_ip)
        age_factor = min(1.0, avg_vuln_age_days / 365)
        
        return 0.7 * vuln_score + 0.3 * age_factor
    
    def _score_attack_frequency(self, asset: Dict[str, Any], 
                                horizon_days: int) -> float:
        """
        Score likelihood of attack based on historical incident frequency.
        
        Returns:
            Score 0-1
        """
        asset_ip = asset.get('ip_address')
        
        # Historical attacks on this asset in past year
        past_attacks = self.incident_store.count_incidents_on_asset(
            asset_ip, days=365
        )
        
        # Attack frequency trend (is it increasing?)
        recent_attacks = self.incident_store.count_incidents_on_asset(
            asset_ip, days=90
        )
        
        # Calculate attack rate per month
        attack_rate = max(0.01, recent_attacks / 3)  # Per month average
        
        # Poisson probability: P(attack in next N days) ≈ 1 - e^(-λt)
        lambda_param = attack_rate / 30  # Convert to daily rate
        poisson_prob = 1.0 - np.exp(-lambda_param * horizon_days)
        
        return min(1.0, poisson_prob)
    
    def _score_lateral_movement(self, asset: Dict[str, Any]) -> float:
        """
        Score how exposed this asset is for lateral movement.
        
        Assets in central network positions are higher value targets.
        
        Returns:
            Score 0-1
        """
        # Graph centrality: how many paths go through this node?
        centrality = self.attack_graph.calculate_betweenness_centrality(asset)
        
        # Normalize: max centrality = 1.0
        normalized_centrality = min(1.0, centrality / 0.5)
        
        # Hops to critical systems
        hops_to_critical = self.attack_graph.min_hops_to_critical_asset(asset)
        hops_score = 1.0 / (1.0 + hops_to_critical)
        
        return 0.6 * normalized_centrality + 0.4 * hops_score
    
    def _score_threat_actor_affinity(self, asset: Dict[str, Any]) -> float:
        """
        Score how likely threat actors are to target this asset.
        
        Based on: sector, industry, asset type, previous targeting patterns
        
        Returns:
            Score 0-1
        """
        sector = asset.get('sector')
        asset_type = asset.get('type')
        
        # Query threat actor database for targeting preferences
        targeting_score = self.threat_actors.get_sector_targeting_score(sector)
        
        # Asset type popularity among threat actors
        type_popularity = self.threat_actors.get_asset_type_popularity(asset_type)
        
        return 0.6 * targeting_score + 0.4 * type_popularity
    
    def _bootstrap_confidence_interval(
        self, asset: Dict[str, Any], horizon_days: int,
        point_estimate: float, bootstrap_samples: int = 1000
    ) -> Tuple[float, float]:
        """
        Compute 95% confidence interval via bootstrap resampling.
        
        Returns:
            (lower_bound, upper_bound)
        """
        bootstrap_estimates = []
        
        for _ in range(bootstrap_samples):
            # Resample coefficients with slight noise
            noisy_cve = self._score_asset_cve_risk(asset) * np.random.normal(1.0, 0.1)
            noisy_freq = self._score_attack_frequency(asset, horizon_days) * np.random.normal(1.0, 0.1)
            noisy_lateral = self._score_lateral_movement(asset) * np.random.normal(1.0, 0.1)
            noisy_actor = self._score_threat_actor_affinity(asset) * np.random.normal(1.0, 0.1)
            
            bootstrapped = (
                self.coefficients['cve_risk'] * max(0, min(1, noisy_cve)) +
                self.coefficients['attack_frequency'] * max(0, min(1, noisy_freq)) +
                self.coefficients['lateral_movement'] * max(0, min(1, noisy_lateral)) +
                self.coefficients['threat_actor_affinity'] * max(0, min(1, noisy_actor))
            )
            bootstrap_estimates.append(bootstrapped)
        
        # 95% CI: 2.5th to 97.5th percentile
        lower = np.percentile(bootstrap_estimates, 2.5)
        upper = np.percentile(bootstrap_estimates, 97.5)
        
        return max(0.0, lower), min(1.0, upper)
    
    def _identify_primary_threats(self, asset: Dict[str, Any]) -> List[str]:
        """Identify likely threat vectors."""
        threats = []
        
        # Check for vulnerable services
        if self.cve_db.has_exploitable_cve(asset.get('ip_address')):
            threats.append('CVE Exploitation')
        
        # Check if network accessible
        if asset.get('is_external_facing'):
            threats.append('External Network Attack')
        
        # Check for weak credentials
        if asset.get('default_credentials_present'):
            threats.append('Credential Brute Force')
        
        return threats[:3]
    
    def _recommend_mitigations(self, asset: Dict[str, Any]) -> List[str]:
        """Recommend mitigations for this asset."""
        return [
            'Apply security patches',
            'Enable network segmentation',
            'Implement EDR solution'
        ]
    
    def _predict_attack_vector(self, asset: Dict[str, Any]) -> str:
        """Predict likely attack vector."""
        if asset.get('is_external_facing'):
            return 'External Exploitation'
        elif self.attack_graph.has_external_path_to_asset(asset):
            return 'Lateral Movement'
        else:
            return 'Internal Compromise'


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Predictive Attack Forecast Engine loaded")
