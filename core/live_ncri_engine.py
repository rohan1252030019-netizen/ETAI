"""
IMMUNEX Elite Phase 3: Live NCRI Engine

Real-time National Cyber Resilience Index calculation with streaming updates,
trend analysis, and risk spike detection.

Author: Principal AI Architect
Date: 2026-06-22
Lines: 420
"""

import logging
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
from collections import deque

logger , timezone= logging.getLogger(__name__)


@dataclass
class NCRISnapshot:
    """Point-in-time NCRI measurement."""
    timestamp: str
    ncri_score: float
    vulnerability_component: float
    exposure_component: float
    response_component: float
    recovery_component: float
    path_accessibility_component: float
    dependency_component: float
    sector_breakdown: Dict[str, float]
    trending: bool
    trend_direction: str  # "UP", "DOWN", "STABLE"
    trend_percent_change: float


class LiveNCRIEngine:
    """
    Real-time NCRI calculator that continuously recalculates national
    cyber resilience based on live feeds of CVEs, incidents, and threats.
    """
    
    # Critical sectors for national resilience
    SECTORS = ["Energy", "Healthcare", "Government", "Telecom", "Education"]
    
    def __init__(self,
                 cve_db: Any,
                 incident_store: Any,
                 attack_graph: Any,
                 postgres_client: Any = None,
                 update_interval_seconds: int = 60):
        """
        Args:
            cve_db: CVE prioritization engine
            incident_store: Incident database
            attack_graph: Attack graph engine
            postgres_client: PostgreSQL connection
            update_interval_seconds: How often to recalculate NCRI
        """
        self.cve_db = cve_db
        self.incident_store = incident_store
        self.attack_graph = attack_graph
        self.postgres_client = postgres_client
        self.update_interval_seconds = update_interval_seconds
        
        # Circular buffers for history
        self.history_buffer = deque(maxlen=1440)  # 24 hours @ 1-min intervals
        self.sector_history = {s: deque(maxlen=1440) for s in self.SECTORS}
        
        # Component weights
        self.weights = {
            "vulnerability": 0.35,
            "exposure": 0.25,
            "response": 0.15,
            "recovery": 0.15,
            "path_accessibility": 0.05,
            "dependency": 0.05
        }
        
        # Current snapshot
        self.current_snapshot: Optional[NCRISnapshot] = None
        self.last_update_time: Optional[datetime] = None
        
        logger.info("LiveNCRIEngine initialized")
    
    def calculate_live_ncri(self) -> NCRISnapshot:
        """
        Calculate current NCRI based on live data feeds.
        
        Returns:
            NCRISnapshot with current score and components
        """
        try:
            # Calculate each component
            vuln_score = self._calculate_vulnerability_component()
            exposure_score = self._calculate_exposure_component()
            response_score = self._calculate_response_component()
            recovery_score = self._calculate_recovery_component()
            path_score = self._calculate_path_accessibility_component()
            dependency_score = self._calculate_dependency_component()
            
            # Weighted geometric mean formula
            ncri_score = self._compute_geometric_mean(
                vuln_score,
                exposure_score,
                response_score,
                recovery_score,
                path_score,
                dependency_score
            )
            
            # Sector breakdown
            sector_scores = self._calculate_sector_breakdown()
            
            # Detect trending
            is_trending, direction, pct_change = self._detect_trend(ncri_score)
            
            snapshot = NCRISnapshot(
                timestamp=datetime.now(timezone.utc).isoformat(),
                ncri_score=ncri_score,
                vulnerability_component=vuln_score,
                exposure_component=exposure_score,
                response_component=response_score,
                recovery_component=recovery_score,
                path_accessibility_component=path_score,
                dependency_component=dependency_score,
                sector_breakdown=sector_scores,
                trending=is_trending,
                trend_direction=direction,
                trend_percent_change=pct_change
            )
            
            # Update history
            self.history_buffer.append(snapshot)
            self.current_snapshot = snapshot
            self.last_update_time = datetime.now(timezone.utc)
            
            # Persist to database
            self._persist_snapshot(snapshot)
            
            # Detect risk spikes
            self._detect_risk_spikes(snapshot)
            
            logger.info("NCRI calculated: %.4f (vuln=%.2f exp=%.2f resp=%.2f rec=%.2f path=%.2f dep=%.2f)",
                       ncri_score, vuln_score, exposure_score, response_score,
                       recovery_score, path_score, dependency_score)
            
            return snapshot
        
        except Exception as e:
            logger.error("Error calculating live NCRI: %s", str(e))
            # Return last known snapshot or default
            if self.current_snapshot:
                return self.current_snapshot
            else:
                return self._default_snapshot()
    
    def _calculate_vulnerability_component(self) -> float:
        """Score based on critical/high-severity unpatched CVEs."""
        try:
            # Query cve_db for current state
            # In prod: total_critical_unpatched = cve_db.count_critical_unpatched()
            #          total_critical_total = cve_db.count_critical_total()
            total_critical_unpatched = 45  # placeholder
            total_critical_total = 150
            
            # Ratio of unpatched critical CVEs
            ratio = total_critical_unpatched / max(1, total_critical_total)
            score = 1.0 - (ratio * 0.5)  # Heavy penalty for unpatched
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.warning("Error calculating vulnerability component: %s", str(e))
            return 0.5
    
    def _calculate_exposure_component(self) -> float:
        """Score based on internet-exposed assets."""
        try:
            # Count exposed hosts
            # In prod: exposed_count = attack_graph.count_internet_exposed()
            #          total_count = attack_graph.number_of_nodes()
            exposed_count = 25
            total_count = 500
            
            exposure_ratio = exposed_count / max(1, total_count)
            score = 1.0 - (exposure_ratio * 0.6)  # Heavy penalty for exposure
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.warning("Error calculating exposure component: %s", str(e))
            return 0.5
    
    def _calculate_response_component(self) -> float:
        """Score based on SOAR automation and playbook coverage."""
        try:
            # Check incident response capability
            # In prod: mean_detection_time = incident_store.mean_detection_time_minutes()
            #          mean_response_time = incident_store.mean_response_time_minutes()
            mean_detection_time = 45  # minutes
            mean_response_time = 120  # minutes
            
            # Faster is better
            # Target: <10 min detection, <60 min response
            detection_score = 1.0 - min(1.0, mean_detection_time / 60.0)
            response_score = 1.0 - min(1.0, mean_response_time / 120.0)
            
            score = (detection_score * 0.6) + (response_score * 0.4)
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.warning("Error calculating response component: %s", str(e))
            return 0.5
    
    def _calculate_recovery_component(self) -> float:
        """Score based on backup/DR readiness."""
        try:
            # Check recovery capabilities
            # In prod: from incident_store
            critical_assets_with_backups = 280
            total_critical_assets = 300
            
            backup_coverage = critical_assets_with_backups / max(1, total_critical_assets)
            score = backup_coverage  # Direct correlation
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.warning("Error calculating recovery component: %s", str(e))
            return 0.5
    
    def _calculate_path_accessibility_component(self) -> float:
        """Score based on attack path length to critical assets."""
        try:
            # Average path length from entry to crown jewel
            # Longer paths = better (requires more hops)
            # In prod: avg_path_length = attack_graph.avg_path_to_critical_asset()
            avg_path_length = 4.2
            
            # Normalize: path_length 2-10 maps to score 0-1
            score = (avg_path_length - 2) / 8.0
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.warning("Error calculating path accessibility component: %s", str(e))
            return 0.5
    
    def _calculate_dependency_component(self) -> float:
        """Score based on sector interdependencies and SoF."""
        try:
            # Assess single points of failure
            # In prod: query incident_store for recent cascade events
            recent_cascades = 2
            total_incidents = 180
            
            cascade_ratio = recent_cascades / max(1, total_incidents)
            score = 1.0 - (cascade_ratio * 0.3)  # Light penalty
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.warning("Error calculating dependency component: %s", str(e))
            return 0.5
    
    def _compute_geometric_mean(self, *components: float) -> float:
        """
        Compute weighted geometric mean.
        
        Formula: NCRI = (V^w_v × E^w_e × R^w_r × REC^w_rec × A^w_a × D^w_d)^(1/6)
        """
        w = list(self.weights.values())
        
        product = 1.0
        for i, comp in enumerate(components):
            # Avoid log(0)
            comp = max(0.01, comp)
            product *= (comp ** w[i])
        
        # 6th root
        ncri = product ** (1.0 / 6.0)
        return max(0.0, min(1.0, ncri))
    
    def _calculate_sector_breakdown(self) -> Dict[str, float]:
        """Calculate NCRI for each critical sector."""
        scores = {}
        for sector in self.SECTORS:
            try:
                # Sector-specific scoring
                # In prod: query incident_store by sector
                base_score = self.current_snapshot.ncri_score if self.current_snapshot else 0.7
                sector_adjustment = {
                    "Energy": -0.05,
                    "Healthcare": 0.0,
                    "Government": -0.10,
                    "Telecom": 0.05,
                    "Education": 0.10
                }.get(sector, 0.0)
                
                sector_score = base_score + sector_adjustment
                scores[sector] = max(0.0, min(1.0, sector_score))
                
                # Track history
                self.sector_history[sector].append(scores[sector])
            except Exception as e:
                logger.warning("Error calculating sector score for %s: %s", sector, str(e))
                scores[sector] = 0.5
        
        return scores
    
    def _detect_trend(self, current_score: float) -> Tuple[bool, str, float]:
        """Detect if NCRI is trending up/down/stable."""
        if len(self.history_buffer) < 2:
            return False, "STABLE", 0.0
        
        # Compare last 10 measurements
        window_size = min(10, len(self.history_buffer))
        recent = list(self.history_buffer)[-window_size:]
        avg_recent = sum(s.ncri_score for s in recent) / window_size
        
        # Compare to older measurements (if available)
        if len(self.history_buffer) >= 20:
            older = list(self.history_buffer)[-20:-10]
            avg_older = sum(s.ncri_score for s in older) / len(older)
        else:
            avg_older = current_score
        
        pct_change = ((avg_recent - avg_older) / max(0.01, avg_older)) * 100
        
        is_trending = abs(pct_change) > 2.0
        direction = "UP" if pct_change > 0 else "DOWN"
        
        return is_trending, direction, pct_change
    
    def _detect_risk_spikes(self, snapshot: NCRISnapshot) -> None:
        """Detect unusual drops in NCRI (risk spikes)."""
        if len(self.history_buffer) < 2:
            return
        
        previous = list(self.history_buffer)[-2]
        drop = previous.ncri_score - snapshot.ncri_score
        
        if drop > 0.15:  # Spike threshold
            logger.warning("NCRI risk spike detected: drop of %.2f (from %.2f to %.2f)",
                          drop, previous.ncri_score, snapshot.ncri_score)
            # Trigger alert (in prod)
    
    def _persist_snapshot(self, snapshot: NCRISnapshot) -> None:
        """Persist snapshot to PostgreSQL."""
        if not self.postgres_client:
            return
        
        try:
            query = """
            INSERT INTO ncri_snapshots 
            (timestamp, ncri_score, vulnerability, exposure, response, recovery, 
             path_accessibility, dependency, sector_breakdown, trending, trend_direction)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            self.postgres_client.execute(query, (
                snapshot.timestamp,
                snapshot.ncri_score,
                snapshot.vulnerability_component,
                snapshot.exposure_component,
                snapshot.response_component,
                snapshot.recovery_component,
                snapshot.path_accessibility_component,
                snapshot.dependency_component,
                json.dumps(snapshot.sector_breakdown),
                snapshot.trending,
                snapshot.trend_direction
            ))
        except Exception as e:
            logger.warning("Failed to persist NCRI snapshot: %s", str(e))
    
    def get_ncri_history(self, hours: int = 24) -> List[NCRISnapshot]:
        """Get NCRI history for past N hours."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=hours)
        
        return [s for s in self.history_buffer 
                if datetime.fromisoformat(s.timestamp) >= cutoff]
    
    def get_sector_trend(self, sector: str, hours: int = 24) -> List[float]:
        """Get trend for a specific sector."""
        if sector not in self.sector_history:
            return []
        
        history = list(self.sector_history[sector])
        window = min(len(history), int(60 * hours / self.update_interval_seconds))
        return history[-window:] if history else []
    
    def _default_snapshot(self) -> NCRISnapshot:
        """Return default snapshot when calculation fails."""
        return NCRISnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            ncri_score=0.50,
            vulnerability_component=0.50,
            exposure_component=0.50,
            response_component=0.50,
            recovery_component=0.50,
            path_accessibility_component=0.50,
            dependency_component=0.50,
            sector_breakdown={s: 0.50 for s in self.SECTORS},
            trending=False,
            trend_direction="STABLE",
            trend_percent_change=0.0
        )
