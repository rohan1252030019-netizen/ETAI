"""
Autonomous Mitigation Planner

Optimizes mitigation sequencing to minimize risk while respecting
cost, downtime, and dependency constraints.

Uses Integer Linear Programming (MILP) or simulated annealing.

Author: IMMUNEX Core Team
"""

from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import logging
from dataclasses import dataclass

logger , timezone= logging.getLogger(__name__)


@dataclass
class MitigationPlan:
    """Optimized mitigation execution plan."""
    plan_id: str
    mitigations: List[Dict[str, Any]]  # {mitigation, priority, deployment_order}
    estimated_risk_reduction: float
    estimated_cost: float
    estimated_downtime_hours: float
    confidence_score: float
    timestamp: datetime


class AutonomousMitigationPlanner:
    """
    Optimizes mitigation sequencing using constraint-based optimization.
    
    Constraints:
        - Minimize total downtime
        - Minimize total cost
        - Respect dependency ordering
        - Maximize risk reduction
    
    Uses PuLP (MILP) or scipy.optimize (simulated annealing).
    """
    
    def __init__(self, cve_db, playbook_engine, soar_orchestrator):
        """
        Initialize mitigation planner.
        
        Args:
            cve_db: CVE database for risk scoring
            playbook_engine: Available mitigations and playbooks
            soar_orchestrator: Orchestration capabilities
        """
        self.cve_db = cve_db
        self.playbook_engine = playbook_engine
        self.soar = soar_orchestrator
    
    def plan_mitigations(
        self,
        critical_assets: List[str],
        budget_dollars: Optional[float] = None,
        max_downtime_hours: Optional[float] = None,
        planning_horizon_days: int = 30
    ) -> MitigationPlan:
        """
        Generate optimized mitigation plan.
        
        Args:
            critical_assets: Asset IPs to prioritize
            budget_dollars: Cost constraint (optional)
            max_downtime_hours: Downtime constraint (optional)
            planning_horizon_days: Planning window
        
        Returns:
            MitigationPlan with sequenced mitigations
        """
        try:
            # Step 1: Enumerate all possible mitigations
            mitigations = self._enumerate_mitigations(critical_assets)
            
            # Step 2: Score each mitigation
            mitigation_scores = self._score_mitigations(mitigations)
            
            # Step 3: Solve optimization problem
            optimal_plan = self._solve_mitigation_optimization(
                mitigations,
                mitigation_scores,
                budget_dollars,
                max_downtime_hours
            )
            
            return optimal_plan
            
        except Exception as e:
            logger.error(f"Error planning mitigations: {e}")
            raise
    
    def _enumerate_mitigations(self, critical_assets: List[str]) -> List[Dict[str, Any]]:
        """Enumerate all possible mitigations for critical assets."""
        mitigations = []
        
        for asset in critical_assets:
            # Get vulnerabilities on this asset
            vulns = self.cve_db.get_vulnerabilities_for_asset(asset)
            
            for vuln in vulns:
                # Get applicable playbooks
                playbooks = self.playbook_engine.get_playbooks_for_cve(vuln['cve_id'])
                
                for playbook in playbooks:
                    mitigation = {
                        'id': f"{asset}_{vuln['cve_id']}_{playbook['id']}",
                        'asset': asset,
                        'cve_id': vuln['cve_id'],
                        'playbook_id': playbook['id'],
                        'mitigation_type': playbook['type'],  # 'patch', 'compensating_control'
                        'risk_reduction': vuln['cvss_score'] * playbook['effectiveness'],
                        'cost_dollars': playbook['cost'],
                        'downtime_hours': playbook['downtime'],
                        'dependencies': playbook.get('depends_on', [])
                    }
                    mitigations.append(mitigation)
        
        return mitigations
    
    def _score_mitigations(self, mitigations: List[Dict]) -> Dict[str, float]:
        """
        Score mitigations by efficiency (risk reduction per unit cost/downtime).
        
        Score = risk_reduction / (cost + downtime_cost)
        """
        scores = {}
        downtime_cost_per_hour = 10000  # $ per hour of downtime
        
        for m in mitigations:
            total_cost = m['cost_dollars'] + (m['downtime_hours'] * downtime_cost_per_hour)
            efficiency = m['risk_reduction'] / max(1, total_cost)
            scores[m['id']] = efficiency
        
        return scores
    
    def _solve_mitigation_optimization(
        self,
        mitigations: List[Dict],
        scores: Dict[str, float],
        budget: Optional[float],
        max_downtime: Optional[float]
    ) -> MitigationPlan:
        """
        Solve MILP to find optimal mitigation set.
        
        Objective: Maximize total risk reduction
        Constraints: 
            - Total cost ≤ budget
            - Total downtime ≤ max_downtime
            - Respect dependencies
        
        Uses PuLP if available, else greedy heuristic.
        """
        try:
            from pulp import LpMaximize, LpProblem, LpVariable, lpSum, value
        except ImportError:
            logger.warning("PuLP not available, using greedy heuristic")
            return self._greedy_mitigation_selection(mitigations, budget, max_downtime)
        
        # Create optimization problem
        prob = LpProblem("Mitigation_Optimization", LpMaximize)
        
        # Decision variables: binary for each mitigation
        x = {m['id']: LpVariable(f"x_{m['id']}", cat='Binary') for m in mitigations}
        
        # Objective: maximize risk reduction
        prob += lpSum([m['risk_reduction'] * x[m['id']] for m in mitigations])
        
        # Constraints
        if budget:
            prob += lpSum([m['cost_dollars'] * x[m['id']] for m in mitigations]) <= budget
        
        if max_downtime:
            prob += lpSum([m['downtime_hours'] * x[m['id']] for m in mitigations]) <= max_downtime
        
        # Dependency constraints: if a mitigation is selected, its dependencies must be too
        for m in mitigations:
            for dep_id in m['dependencies']:
                if dep_id in x:
                    prob += x[m['id']] <= x[dep_id]
        
        # Solve
        prob.solve(timeLimit=30)  # 30-second timeout
        
        # Extract solution
        selected_mitigations = [m for m in mitigations if value(x[m['id']]) > 0.5]
        
        # Sort by dependency order
        selected_mitigations = self._topological_sort_mitigations(selected_mitigations)
        
        total_risk_reduction = sum(m['risk_reduction'] for m in selected_mitigations)
        total_cost = sum(m['cost_dollars'] for m in selected_mitigations)
        total_downtime = sum(m['downtime_hours'] for m in selected_mitigations)
        
        plan = MitigationPlan(
            plan_id=f"plan_{datetime.now(timezone.utc).isoformat()}",
            mitigations=selected_mitigations,
            estimated_risk_reduction=total_risk_reduction,
            estimated_cost=total_cost,
            estimated_downtime_hours=total_downtime,
            confidence_score=0.85,
            timestamp=datetime.now(timezone.utc)
        )
        
        return plan
    
    def _greedy_mitigation_selection(
        self,
        mitigations: List[Dict],
        budget: Optional[float],
        max_downtime: Optional[float]
    ) -> MitigationPlan:
        """Fallback greedy heuristic if MILP solver unavailable."""
        # Sort by risk reduction / cost ratio
        sorted_mits = sorted(
            mitigations,
            key=lambda m: m['risk_reduction'] / max(1, m['cost_dollars']),
            reverse=True
        )
        
        selected = []
        total_cost = 0
        total_downtime = 0
        
        for m in sorted_mits:
            if budget and total_cost + m['cost_dollars'] > budget:
                continue
            if max_downtime and total_downtime + m['downtime_hours'] > max_downtime:
                continue
            
            selected.append(m)
            total_cost += m['cost_dollars']
            total_downtime += m['downtime_hours']
        
        return MitigationPlan(
            plan_id=f"plan_{datetime.now(timezone.utc).isoformat()}",
            mitigations=selected,
            estimated_risk_reduction=sum(m['risk_reduction'] for m in selected),
            estimated_cost=total_cost,
            estimated_downtime_hours=total_downtime,
            confidence_score=0.70,
            timestamp=datetime.now(timezone.utc)
        )
    
    def _topological_sort_mitigations(self, mitigations: List[Dict]) -> List[Dict]:
        """Sort mitigations by dependency order (dependencies first)."""
        # Simple topological sort
        sorted_list = []
        remaining = set(m['id'] for m in mitigations)
        
        while remaining:
            # Find mitigation with no unsatisfied dependencies
            for m in mitigations:
                if m['id'] not in remaining:
                    continue
                
                unsatisfied = [d for d in m['dependencies'] if d in remaining]
                if not unsatisfied:
                    sorted_list.append(m)
                    remaining.discard(m['id'])
                    break
        
        return sorted_list


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Autonomous Mitigation Planner loaded")
