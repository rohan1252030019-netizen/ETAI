"""
CNI-Resilience Cross-Sector Cascading Impact Simulator
======================================================
Simulates secondary and tertiary failure propagation paths across CNI sectors 
resulting from primary network compromises or system shutdowns.
"""

from __future__ import annotations
import networkx as nx
from typing import Any, Dict, List
from utils.logger import log

class CascadingFailureSimulator:
    def __init__(self) -> None:
        self.dependency_graph = nx.DiGraph()
        self._build_sector_dependency_graph()

    def _build_sector_dependency_graph(self) -> None:
        """
        Builds the national sector dependency graph representing how sectors power/serve each other.
        """
        # Node structures
        sectors = {
            "ENERGY_GRID": {"name": "Energy Grid", "criticality": 0.98},
            "HEALTHCARE": {"name": "Healthcare / Hospital Systems", "criticality": 0.95},
            "GOVERNMENT": {"name": "Government Services / Public Security", "criticality": 0.92},
            "TELECOM": {"name": "Telecommunications & ISP Network", "criticality": 0.90},
            "EDUCATION": {"name": "National Education & Universities Network", "criticality": 0.70}
        }
        
        for code, attrs in sectors.items():
            self.dependency_graph.add_node(code, **attrs)

        # Directed dependencies (edges: Source supports Target)
        # Weight represents dependency strength (0.0 to 1.0)
        # Delay represents duration in hours before failure cascades if source goes down
        dependencies = [
            ("ENERGY_GRID", "HEALTHCARE", {"weight": 0.95, "delay_hours": 8.0, "type": "power", "impact": "Life support systems battery exhaustion, ICU backup generators depletion"}),
            ("ENERGY_GRID", "TELECOM", {"weight": 0.90, "delay_hours": 4.0, "type": "power", "impact": "Cell tower battery backups drain, routing core shutdowns"}),
            ("ENERGY_GRID", "GOVERNMENT", {"weight": 0.85, "delay_hours": 12.0, "type": "power", "impact": "Public records offline, police communication repeaters down"}),
            ("TELECOM", "GOVERNMENT", {"weight": 0.80, "delay_hours": 0.5, "type": "communications", "impact": "Emergency response dispatch (e.g. 100/112) system routing failure"}),
            ("TELECOM", "HEALTHCARE", {"weight": 0.75, "delay_hours": 1.0, "type": "communications", "impact": "PACS image retrieval servers disconnected, ambulance telemetry dropped"}),
            ("GOVERNMENT", "EDUCATION", {"weight": 0.60, "delay_hours": 24.0, "type": "auth", "impact": "State credentials validation service offline, research servers lock"}),
            ("TELECOM", "EDUCATION", {"weight": 0.70, "delay_hours": 2.0, "type": "network", "impact": "Online examination portals offline, university databases unavailable"})
        ]
        
        for u, v, attrs in dependencies:
            self.dependency_graph.add_edge(u, v, **attrs)

    def simulate_failure(self, primary_sector_failed: str) -> Dict[str, Any]:
        """
        Traces the cascade path from a primary sector failure to calculate secondary and tertiary impacts.
        """
        if primary_sector_failed not in self.dependency_graph:
            return {"status": "ERROR", "message": f"Sector '{primary_sector_failed}' not found in dependency model"}

        timeline: List[Dict[str, Any]] = []
        visited = {primary_sector_failed: 0.0}  # Map of sector -> time_of_failure
        
        # Step 1: Add initial event
        timeline.append({
            "sector": primary_sector_failed,
            "name": self.dependency_graph.nodes[primary_sector_failed]["name"],
            "cascade_level": "PRIMARY",
            "hours_offset": 0.0,
            "impact_description": "Initial primary system compromise / shutdown",
            "citizen_impact": "Loss of primary systems, system transition to manual overrides.",
            "economic_loss_score": 8.5
        })

        # Step 2: Queue for BFS traversal to find cascades
        queue = [(primary_sector_failed, 0.0)]  # (sector, cumulative_hours)
        
        while queue:
            curr_sector, curr_time = queue.pop(0)
            
            for neighbor in self.dependency_graph.neighbors(curr_sector):
                edge_data = self.dependency_graph.get_edge_data(curr_sector, neighbor)
                delay = edge_data["delay_hours"]
                cascade_time = curr_time + delay
                
                # If neighbor was not visited or we found a quicker cascading pathway
                if neighbor not in visited or visited[neighbor] > cascade_time:
                    visited[neighbor] = cascade_time
                    
                    # Determine secondary vs tertiary based on depth/hops
                    path_len = len(nx.shortest_path(self.dependency_graph, source=primary_sector_failed, target=neighbor)) - 1
                    level = "SECONDARY" if path_len == 1 else "TERTIARY"
                    
                    # Quantify citizen and economic impact details
                    citizen_impact = ""
                    economic_loss = 5.0
                    
                    if neighbor == "HEALTHCARE":
                        citizen_impact = "Critical danger to patients requiring continuous life support, ICU disruption, ER redirections."
                        economic_loss = 9.0
                    elif neighbor == "TELECOM":
                        citizen_impact = "Loss of voice and internet connectivity for citizens, inability to make phone calls."
                        economic_loss = 7.5
                    elif neighbor == "GOVERNMENT":
                        citizen_impact = "Interruption of municipal utility grids, security coordination networks offline."
                        economic_loss = 8.0
                    elif neighbor == "EDUCATION":
                        citizen_impact = "Suspension of educational activities, research databases locked."
                        economic_loss = 3.5

                    timeline.append({
                        "sector": neighbor,
                        "name": self.dependency_graph.nodes[neighbor]["name"],
                        "cascade_level": level,
                        "hours_offset": round(cascade_time, 2),
                        "impact_description": edge_data["impact"],
                        "citizen_impact": citizen_impact,
                        "economic_loss_score": economic_loss
                    })
                    queue.append((neighbor, cascade_time))

        # Sort timeline by time offset
        timeline = sorted(timeline, key=lambda x: x["hours_offset"])

        # Calculate composite metrics
        total_sectors_compromised = len(timeline)
        avg_economic_score = sum(x["economic_loss_score"] for x in timeline) / len(timeline)
        
        return {
            "primary_sector": primary_sector_failed,
            "total_sectors_affected": total_sectors_compromised,
            "impact_timeline": timeline,
            "national_economic_threat_level": round(avg_economic_score, 2),
            "remediation_urgency": "CRITICAL" if avg_economic_score > 7.0 else "HIGH"
        }
