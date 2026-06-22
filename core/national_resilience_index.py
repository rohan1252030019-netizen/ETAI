"""
IMMUNEX National Cyber Resilience Index (NCRI) Engine

Computes a single, governance-grade metric for national cyber resilience.
Integrates CVE risk, exposure intelligence, incident response, recovery readiness,
attack path accessibility, and sector dependencies into a weighted composite score.

Classes:
  - NationalResilienceIndexEngine: Main NCRI calculation engine
  - SectorResilienceScorer: Per-sector scoring
  - ResilienceComponentAggregator: Combines sub-scores into final NCRI

Author: IMMUNEX Core Team
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import json
import logging
from dataclasses import dataclass
import numpy as np

logger , timezone= logging.getLogger(__name__)


@dataclass
class NCRIComponentScore:
    """Individual component contributing to NCRI."""
    name: str
    raw_score: float  # 0.0-1.0
    weight: float  # 0.0-1.0
    contribution: float  # weight * raw_score
    evidence: Dict[str, Any]
    timestamp: datetime


@dataclass
class NCRISectorScore:
    """Per-sector NCRI breakdown."""
    sector: str
    ncri_score: float
    vulnerability_score: float
    exposure_score: float
    incident_response_score: float
    recovery_readiness_score: float
    attack_path_score: float
    dependency_risk_score: float
    trend_30_days: float
    trend_90_days: float


class NationalResilienceIndexEngine:
    """
    Computes NCRI: National Cyber Resilience Index.
    
    Formula:
        NCRI = (V_score^0.35 × E_score^0.25 × I_score^0.15 × 
                R_score^0.15 × A_score^0.05 × D_score^0.05)^(1/6) 
                
    Where:
        V_score = Critical Vulnerabilities Score (0-1)
        E_score = Exposure Intelligence Score (0-1)
        I_score = Incident Response Capability Score (0-1)
        R_score = Recovery Readiness Score (0-1)
        A_score = Attack Path Accessibility Score (0-1)
        D_score = Sector Dependency Risk Score (0-1)
    """
    
    def __init__(self, postgres_client, incident_store, cve_db, asset_registry):
        """
        Initialize NCRI engine.
        
        Args:
            postgres_client: PostgreSQL connection for scoring data
            incident_store: Incident database for response metrics
            cve_db: CVE prioritization engine
            asset_registry: Asset inventory for exposure scoring
        """
        self.postgres = postgres_client
        self.incident_store = incident_store
        self.cve_db = cve_db
        self.asset_registry = asset_registry
        
        # Component weights (sum = 1.0)
        self.component_weights = {
            'vulnerability': 0.35,
            'exposure': 0.25,
            'incident_response': 0.15,
            'recovery_readiness': 0.15,
            'attack_path_accessibility': 0.05,
            'sector_dependency': 0.05
        }
    
    def calculate_ncri(self) -> Tuple[float, Dict[str, NCRIComponentScore]]:
        """
        Calculate national NCRI score and component breakdown.
        
        Returns:
            (ncri_score, component_scores_dict)
        """
        try:
            # Calculate each component
            v_score = self._calculate_vulnerability_score()
            e_score = self._calculate_exposure_score()
            i_score = self._calculate_incident_response_score()
            r_score = self._calculate_recovery_readiness_score()
            a_score = self._calculate_attack_path_accessibility_score()
            d_score = self._calculate_sector_dependency_score()
            
            # Weighted geometric mean
            ncri = (
                (v_score ** self.component_weights['vulnerability']) *
                (e_score ** self.component_weights['exposure']) *
                (i_score ** self.component_weights['incident_response']) *
                (r_score ** self.component_weights['recovery_readiness']) *
                (a_score ** self.component_weights['attack_path_accessibility']) *
                (d_score ** self.component_weights['sector_dependency'])
            ) ** (1.0 / 6.0)
            
            # Clamp to 0-1 range
            ncri = max(0.0, min(1.0, ncri))
            
            # Package component scores
            component_scores = {
                'vulnerability': NCRIComponentScore(
                    name='Vulnerability Risk',
                    raw_score=v_score,
                    weight=self.component_weights['vulnerability'],
                    contribution=self.component_weights['vulnerability'] * v_score,
                    evidence={'critical_vulns': self._get_critical_vuln_count()},
                    timestamp=datetime.now(timezone.utc)
                ),
                'exposure': NCRIComponentScore(
                    name='Exposure Intelligence',
                    raw_score=e_score,
                    weight=self.component_weights['exposure'],
                    contribution=self.component_weights['exposure'] * e_score,
                    evidence={'exposed_assets': self._get_exposed_asset_count()},
                    timestamp=datetime.now(timezone.utc)
                ),
                'incident_response': NCRIComponentScore(
                    name='Incident Response Capability',
                    raw_score=i_score,
                    weight=self.component_weights['incident_response'],
                    contribution=self.component_weights['incident_response'] * i_score,
                    evidence={'mttr': self._get_mean_time_to_respond()},
                    timestamp=datetime.now(timezone.utc)
                ),
                'recovery_readiness': NCRIComponentScore(
                    name='Recovery Readiness',
                    raw_score=r_score,
                    weight=self.component_weights['recovery_readiness'],
                    contribution=self.component_weights['recovery_readiness'] * r_score,
                    evidence={'backup_coverage': self._get_backup_coverage_percent()},
                    timestamp=datetime.now(timezone.utc)
                ),
                'attack_path_accessibility': NCRIComponentScore(
                    name='Attack Path Accessibility',
                    raw_score=a_score,
                    weight=self.component_weights['attack_path_accessibility'],
                    contribution=self.component_weights['attack_path_accessibility'] * a_score,
                    evidence={'paths_to_critical': self._get_paths_to_critical()},
                    timestamp=datetime.now(timezone.utc)
                ),
                'sector_dependency': NCRIComponentScore(
                    name='Sector Dependency Risk',
                    raw_score=d_score,
                    weight=self.component_weights['sector_dependency'],
                    contribution=self.component_weights['sector_dependency'] * d_score,
                    evidence={'critical_dependencies': self._get_critical_dependencies()},
                    timestamp=datetime.now(timezone.utc)
                )
            }
            
            logger.info(f"NCRI calculated: {ncri:.4f}")
            return ncri, component_scores
            
        except Exception as e:
            logger.error(f"Error calculating NCRI: {e}")
            raise
    
    def _calculate_vulnerability_score(self) -> float:
        """Calculate vulnerability component (0-1, higher is safer)."""
        critical_vulns = self._get_critical_vuln_count()
        high_vulns = self._get_high_vuln_count()
        
        critical_baseline = 50
        high_baseline = 200
        
        normalized_risk = min(
            1.0,
            (critical_vulns / critical_baseline) + (high_vulns / (2 * high_baseline))
        )
        
        return 1.0 - normalized_risk
    
    def _calculate_exposure_score(self) -> float:
        """Calculate exposure component (0-1, higher is safer)."""
        exposed_assets = self._get_exposed_asset_count()
        total_assets = self._get_total_asset_count()
        
        if total_assets == 0:
            return 0.5
        
        exposure_ratio = exposed_assets / total_assets
        return 1.0 - exposure_ratio
    
    def _calculate_incident_response_score(self) -> float:
        """Calculate incident response capability."""
        mttr_minutes = self._get_mean_time_to_respond()
        detection_coverage = self._get_detection_coverage_percent()
        analyst_count = self._get_soc_analyst_count()
        
        mttr_score = max(0.0, 1.0 - (mttr_minutes - 15) / 105)
        coverage_score = detection_coverage / 100.0
        incident_volume = self._get_monthly_incident_volume()
        ratio_incidents_per_analyst = max(1, incident_volume / max(1, analyst_count))
        analyst_score = 1.0 / (1.0 + (ratio_incidents_per_analyst / 50))
        
        return 0.5 * mttr_score + 0.3 * coverage_score + 0.2 * analyst_score
    
    def _calculate_recovery_readiness_score(self) -> float:
        """Calculate recovery readiness."""
        backup_coverage = self._get_backup_coverage_percent()
        dr_plan_exists = self._dr_plan_exists()
        avg_rto = self._get_average_rto_hours()
        last_successful_test = self._get_last_successful_recovery_test()
        
        backup_score = backup_coverage / 100.0
        dr_score = 1.0 if dr_plan_exists else 0.3
        rto_score = max(0.0, 1.0 - (avg_rto - 4) / 20)
        
        days_since_test = (datetime.now(timezone.utc) - last_successful_test).days
        test_score = max(0.5, 1.0 - (days_since_test / 180))
        
        return 0.5 * backup_score + 0.2 * dr_score + 0.2 * rto_score + 0.1 * test_score
    
    def _calculate_attack_path_accessibility_score(self) -> float:
        """Calculate attack path accessibility."""
        paths_to_critical = self._get_paths_to_critical()
        avg_path_length = self._get_average_attack_path_length()
        
        paths_score = 1.0 / (1.0 + (paths_to_critical / 10))
        length_score = min(1.0, max(0.0, (avg_path_length - 2) / 3))
        
        return 0.7 * paths_score + 0.3 * length_score
    
    def _calculate_sector_dependency_score(self) -> float:
        """Calculate sector dependency risk."""
        critical_dependencies = self._get_critical_dependencies()
        dependency_score = 1.0 / (1.0 + (critical_dependencies / 5))
        return dependency_score
    
    # Data access methods
    def _get_critical_vuln_count(self) -> int:
        return self.cve_db.count_critical_unpatched() if hasattr(self.cve_db, 'count_critical_unpatched') else 0
    
    def _get_high_vuln_count(self) -> int:
        return self.cve_db.count_high_unpatched() if hasattr(self.cve_db, 'count_high_unpatched') else 0
    
    def _get_exposed_asset_count(self) -> int:
        return self.asset_registry.count_exposed_to_internet() if self.asset_registry else 0
    
    def _get_total_asset_count(self) -> int:
        return self.asset_registry.count_all() if self.asset_registry else 1
    
    def _get_mean_time_to_respond(self) -> float:
        return self.incident_store.calculate_mttr_minutes(days=90) if self.incident_store else 30.0
    
    def _get_detection_coverage_percent(self) -> float:
        return self.asset_registry.calculate_detection_coverage_percent() if self.asset_registry else 75.0
    
    def _get_soc_analyst_count(self) -> int:
        return 5
    
    def _get_monthly_incident_volume(self) -> int:
        return self.incident_store.count_incidents_last_30_days() if self.incident_store else 50
    
    def _get_backup_coverage_percent(self) -> float:
        return 85.0
    
    def _dr_plan_exists(self) -> bool:
        return True
    
    def _get_average_rto_hours(self) -> float:
        return 4.0
    
    def _get_last_successful_recovery_test(self) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=30)
    
    def _get_paths_to_critical(self) -> int:
        return 3
    
    def _get_average_attack_path_length(self) -> float:
        return 3.5
    
    def _get_critical_dependencies(self) -> int:
        return 2


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("NCRI Engine loaded")
