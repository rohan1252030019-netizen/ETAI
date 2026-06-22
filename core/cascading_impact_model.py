"""
Cascading Impact Model

Simulates cross-sector impact when critical infrastructure is compromised.

Tracks:
    - Primary impact
    - Secondary impact (dependent sectors)
    - Tertiary impact (cascading further)
    - Economic impact
    - Citizen impact

Author: IMMUNEX Core Team
"""

from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass

logger , timezone= logging.getLogger(__name__)


@dataclass
class CascadingImpactAnalysis:
    """Results of cascading impact simulation."""
    scenario_id: str
    compromised_sector: str
    primary_impact_severity: float  # 0-1
    secondary_affected_sectors: Dict[str, float]  # {sector: impact_severity}
    tertiary_affected_sectors: Dict[str, float]
    economic_impact_dollars: float
    citizen_impact_description: str
    recovery_time_hours: float
    generated_at: datetime


class CascadingFailureSimulator:
    """
    Simulates impact propagation across critical infrastructure sectors.
    
    Sectors:
        - Energy
        - Healthcare
        - Government
        - Telecom
        - Education
    
    Models:
        - Direct dependencies (power, Internet)
        - Supply chain impact
        - Service disruption
        - Cascading failures
    """
    
    def __init__(self, neo4j_client):
        """
        Initialize simulator.
        
        Args:
            neo4j_client: Neo4j for sector dependency graph
        """
        self.neo4j = neo4j_client
        
        # Sector dependency matrix (from domain expertise)
        # Format: {affected_sector: {dependent_sector: impact_factor}}
        self.sector_dependencies = {
            'Energy': {
                'Healthcare': 0.95,  # Healthcare critically dependent on power
                'Government': 0.80,
                'Telecom': 0.75,
                'Education': 0.60
            },
            'Healthcare': {
                'Telecom': 0.70,  # Healthcare needs communication
                'Energy': 0.30,  # Healthcare has backup power
                'Government': 0.20,
                'Education': 0.10
            },
            'Telecom': {
                'Energy': 0.85,
                'Healthcare': 0.60,
                'Government': 0.80,
                'Education': 0.50
            },
            'Government': {
                'Energy': 0.70,
                'Telecom': 0.75,
                'Healthcare': 0.40,
                'Education': 0.30
            },
            'Education': {
                'Telecom': 0.40,
                'Government': 0.35,
                'Energy': 0.50,
                'Healthcare': 0.10
            }
        }
    
    def simulate_sector_compromise(
        self,
        compromised_sector: str,
        attacker_capability: str = 'intermediate'  # novice, intermediate, advanced
    ) -> CascadingImpactAnalysis:
        """
        Simulate impact of sector compromise.
        
        Args:
            compromised_sector: One of {Energy, Healthcare, Government, Telecom, Education}
            attacker_capability: Determines damage severity
        
        Returns:
            CascadingImpactAnalysis with multi-hop impact
        """
        try:
            # Step 1: Calculate primary impact
            capability_map = {
                'novice': 0.3,
                'intermediate': 0.6,
                'advanced': 0.95
            }
            primary_severity = capability_map.get(attacker_capability, 0.6)
            
            # Step 2: Propagate to secondary sectors
            secondary_impacts = self._calculate_secondary_impacts(
                compromised_sector, primary_severity
            )
            
            # Step 3: Propagate to tertiary sectors
            tertiary_impacts = self._calculate_tertiary_impacts(
                secondary_impacts, primary_severity
            )
            
            # Step 4: Calculate economic impact
            economic_impact = self._estimate_economic_impact(
                compromised_sector, primary_severity, secondary_impacts
            )
            
            # Step 5: Estimate citizen impact
            citizen_impact = self._estimate_citizen_impact(
                compromised_sector, secondary_impacts
            )
            
            # Step 6: Estimate recovery time
            recovery_time = self._estimate_recovery_time(
                compromised_sector, secondary_impacts
            )
            
            return CascadingImpactAnalysis(
                scenario_id=f"cascade_{compromised_sector}_{datetime.now(timezone.utc).isoformat()}",
                compromised_sector=compromised_sector,
                primary_impact_severity=primary_severity,
                secondary_affected_sectors=secondary_impacts,
                tertiary_affected_sectors=tertiary_impacts,
                economic_impact_dollars=economic_impact,
                citizen_impact_description=citizen_impact,
                recovery_time_hours=recovery_time,
                generated_at=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            logger.error(f"Error in cascade simulation: {e}")
            raise
    
    def _calculate_secondary_impacts(
        self,
        compromised_sector: str,
        primary_severity: float
    ) -> Dict[str, float]:
        """
        Calculate second-order impacts.
        
        Impact = dependency_factor × primary_severity
        """
        secondary_impacts = {}
        
        dependencies = self.sector_dependencies.get(compromised_sector, {})
        
        for dependent_sector, dependency_factor in dependencies.items():
            # Decay: secondary impacts are at most 100% of dependency factor
            impact_severity = min(1.0, primary_severity * dependency_factor)
            
            if impact_severity > 0.2:  # Only include significant impacts
                secondary_impacts[dependent_sector] = impact_severity
        
        return secondary_impacts
    
    def _calculate_tertiary_impacts(
        self,
        secondary_impacts: Dict[str, float],
        primary_severity: float
    ) -> Dict[str, float]:
        """
        Calculate third-order impacts.
        
        Tertiary impacts are 50% severity of secondary.
        """
        tertiary_impacts = {}
        
        for secondary_sector, secondary_severity in secondary_impacts.items():
            # Tertiary decay: 50% of secondary severity
            dependencies = self.sector_dependencies.get(secondary_sector, {})
            
            for tertiary_sector, dependency_factor in dependencies.items():
                if tertiary_sector in secondary_impacts:
                    continue  # Already counted as secondary
                
                impact_severity = min(1.0, secondary_severity * dependency_factor * 0.5)
                
                if impact_severity > 0.1:
                    tertiary_impacts[tertiary_sector] = impact_severity
        
        return tertiary_impacts
    
    def _estimate_economic_impact(
        self,
        compromised_sector: str,
        primary_severity: float,
        secondary_impacts: Dict[str, float]
    ) -> float:
        """
        Estimate economic impact in dollars.
        
        Based on: sector size, recovery cost, business interruption
        """
        # Per-sector economic base (annual contribution to GDP-like metric)
        sector_economic_base = {
            'Energy': 500e9,        # $500B annual
            'Healthcare': 800e9,    # $800B annual
            'Telecom': 300e9,       # $300B annual
            'Government': 200e9,    # $200B annual
            'Education': 100e9      # $100B annual
        }
        
        # Loss per day as % of annual base
        daily_loss_percent = {
            'novice': 0.1,      # 0.1% per day
            'intermediate': 0.5,  # 0.5% per day
            'advanced': 2.0       # 2.0% per day
        }
        
        base_economic = sector_economic_base.get(compromised_sector, 100e9)
        
        # Estimate recovery time (3-10 days depending on sector)
        recovery_days = {
            'Energy': 7,
            'Healthcare': 3,
            'Telecom': 5,
            'Government': 6,
            'Education': 4
        }.get(compromised_sector, 5)
        
        # Daily loss rate
        daily_loss_rate = daily_loss_percent['intermediate'] * primary_severity / 100
        
        # Primary impact cost
        primary_cost = base_economic * daily_loss_rate * recovery_days
        
        # Secondary sector costs
        secondary_cost = 0
        for sector, severity in secondary_impacts.items():
            sector_base = sector_economic_base.get(sector, 100e9)
            sector_daily_loss = daily_loss_percent['intermediate'] * severity / 100
            secondary_cost += sector_base * sector_daily_loss * (recovery_days / 2)
        
        total_cost = primary_cost + secondary_cost
        
        return total_cost
    
    def _estimate_citizen_impact(
        self,
        compromised_sector: str,
        secondary_impacts: Dict[str, float]
    ) -> str:
        """
        Describe citizen-level impact.
        
        Returns:
            Human-readable description of impact on citizens
        """
        impacts = []
        
        # Primary impact
        if compromised_sector == 'Energy':
            impacts.append(f'Power outages affecting 10-50% of grid')
        elif compromised_sector == 'Healthcare':
            impacts.append('Hospital systems offline, emergency procedures impacted')
        elif compromised_sector == 'Telecom':
            impacts.append('Internet/cellular disruptions affecting communication')
        elif compromised_sector == 'Government':
            impacts.append('Government services disrupted, public records inaccessible')
        elif compromised_sector == 'Education':
            impacts.append('Schools unable to access student data or learning platforms')
        
        # Secondary impacts
        for sector, severity in secondary_impacts.items():
            if severity > 0.6:
                if sector == 'Healthcare':
                    impacts.append('Ambulance delays due to communication issues')
                elif sector == 'Energy':
                    impacts.append('Cascading power failures to dependent infrastructure')
                elif sector == 'Telecom':
                    impacts.append('Emergency services unable to communicate')
        
        return ' | '.join(impacts) if impacts else 'Minimal citizen impact'
    
    def _estimate_recovery_time(
        self,
        compromised_sector: str,
        secondary_impacts: Dict[str, float]
    ) -> float:
        """
        Estimate time to full recovery in hours.
        """
        base_recovery_hours = {
            'Energy': 168,          # 1 week
            'Healthcare': 72,       # 3 days
            'Telecom': 120,         # 5 days
            'Government': 144,      # 6 days
            'Education': 96         # 4 days
        }.get(compromised_sector, 96)
        
        # Add time for secondary impact recovery
        secondary_hours = sum(
            hours * 24 for sector, hours in secondary_impacts.items()
        ) if secondary_impacts else 0
        
        return base_recovery_hours + (secondary_hours * 0.3)


class SectorDependencyGraph:
    """
    Graph representing dependencies between critical sectors.
    
    Used for impact analysis and simulation.
    """
    
    def __init__(self, neo4j_client):
        self.neo4j = neo4j_client
    
    def get_dependent_sectors(self, sector: str) -> List[Tuple[str, float]]:
        """
        Get sectors dependent on given sector.
        
        Returns:
            List of (sector, dependency_strength) tuples
        """
        # Would query Neo4j in real implementation
        return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Cascading Impact Model loaded")
