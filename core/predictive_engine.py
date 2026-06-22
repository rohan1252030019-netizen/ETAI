"""
CNI-Resilience Predictive Attack Forecast Engine
=================================================
Calculates lateral movement probabilities, future blast radius, and forecasts 
adversary routes using Markov-based transition probabilities.
"""

from __future__ import annotations
import networkx as nx
from typing import Any, Dict, List, Tuple
from utils.logger import log

class PredictiveForecastEngine:
    def __init__(self, graph: nx.DiGraph) -> None:
        self.graph = graph

    def predict_next_hop(self, compromised_node: str) -> List[Dict[str, Any]]:
        """
        Calculates next-hop probabilities for adjacent nodes of a compromised node.
        Probability formula:
            P(node) = (exploitability * trust) / Sum(exploitability * trust of neighbors)
        """
        if compromised_node not in self.graph:
            log.warning("compromised_node not found in graph", compromised_node=compromised_node)
            return []

        neighbors = list(self.graph.neighbors(compromised_node))
        if not neighbors:
            return []

        raw_scores = {}
        total_score = 0.0

        for n in neighbors:
            edge_data = self.graph.get_edge_data(compromised_node, n) or {}
            node_data = self.graph.nodes[n]
            
            # Extract trust coefficient (default: 1.0; low trust means firewalled/monitored)
            trust = edge_data.get("trust_coefficient", 1.0)
            if "weight" in edge_data:
                # If weights are used as distance/cost, trust is inversely proportional
                trust = 1.0 / max(edge_data["weight"], 0.01)
                
            # Extract node exploitability (default: 0.3)
            exploitability = node_data.get("exploitability", 0.3)
            if node_data.get("has_kev", False) or node_data.get("in_kev", False):
                exploitability = min(exploitability * 1.5, 1.0)

            score = exploitability * trust
            raw_scores[n] = score
            total_score += score

        results = []
        for n in neighbors:
            prob = (raw_scores[n] / total_score) if total_score > 0 else (1.0 / len(neighbors))
            results.append({
                "target_ip": n,
                "hostname": self.graph.nodes[n].get("hostname", ""),
                "asset_type": self.graph.nodes[n].get("asset_type", "unknown"),
                "zone": self.graph.nodes[n].get("zone", "unknown"),
                "probability": round(prob, 4)
            })

        return sorted(results, key=lambda x: x["probability"], reverse=True)

    def forecast_route_to_target(self, start_node: str, target_node: str, max_hops: int = 5) -> Dict[str, Any]:
        """
        Calculates the most probable paths from start_node to target_node using
        Dijkstra-based paths weighted by negative log probability of transitions.
        """
        if start_node not in self.graph or target_node not in self.graph:
            return {"status": "ERROR", "message": "Start or target node missing from topology"}

        # Build a temporary copy of the graph with transition log weights for pathing
        path_graph = nx.DiGraph()
        for node in self.graph.nodes:
            path_graph.add_node(node, **self.graph.nodes[node])

        for u, v in self.graph.edges:
            edge_data = self.graph.get_edge_data(u, v) or {}
            # Base probability calculation factors
            trust = edge_data.get("trust_coefficient", 1.0)
            exploitability = self.graph.nodes[v].get("exploitability", 0.3)
            score = max(exploitability * trust, 0.01)
            # Use inverse score as weight (cost) for pathing algorithms
            cost = 1.0 / score
            path_graph.add_edge(u, v, cost=cost)

        try:
            shortest_path = nx.shortest_path(path_graph, source=start_node, target=target_node, weight="cost")
            if len(shortest_path) > max_hops + 1:
                return {"status": "TIMEOUT", "message": f"Path exceeds max hops limit of {max_hops}"}
            
            steps = []
            cumulative_probability = 1.0
            
            for i in range(len(shortest_path) - 1):
                curr = shortest_path[i]
                nxt = shortest_path[i+1]
                
                # Calculate probability of this transition among current neighbors
                nxt_probs = self.predict_next_hop(curr)
                nxt_prob_val = 0.1  # fallback
                for item in nxt_probs:
                    if item["target_ip"] == nxt:
                        nxt_prob_val = item["probability"]
                        break
                
                cumulative_probability *= nxt_prob_val
                steps.append({
                    "step": i + 1,
                    "from_ip": curr,
                    "to_ip": nxt,
                    "transition_probability": round(nxt_prob_val, 4)
                })

            return {
                "status": "SUCCESS",
                "path": shortest_path,
                "steps": steps,
                "overall_probability": round(cumulative_probability, 6)
            }
        except nx.NetworkXNoPath:
            return {"status": "NOPATH", "message": "No direct or indirect route exists between nodes"}

    def predict_future_blast_radius(self, compromised_node: str, depth: int = 2) -> Dict[str, Any]:
        """
        Computes predictive blast radius with time-decay probability.
        """
        if compromised_node not in self.graph:
            return {"total_affected": 0, "affected_nodes": []}

        affected = {}
        # BFS traversal up to depth
        queue = [(compromised_node, 1.0, 0)]  # (node, path_probability, current_depth)
        
        while queue:
            curr, prob, curr_depth = queue.pop(0)
            if curr != compromised_node:
                if curr not in affected or affected[curr] < prob:
                    affected[curr] = prob
            
            if curr_depth < depth:
                next_hops = self.predict_next_hop(curr)
                for hop in next_hops:
                    neighbor = hop["target_ip"]
                    hop_prob = hop["probability"]
                    queue.append((neighbor, prob * hop_prob, curr_depth + 1))

        affected_list = []
        for node, prob in affected.items():
            node_data = self.graph.nodes[node]
            affected_list.append({
                "ip": node,
                "hostname": node_data.get("hostname", ""),
                "asset_type": node_data.get("asset_type", "generic"),
                "zone": node_data.get("zone", "unknown"),
                "compromise_probability": round(prob, 4),
                "criticality": node_data.get("criticality", 0.5)
            })

        return {
            "compromised_node": compromised_node,
            "total_affected": len(affected_list),
            "affected_nodes": sorted(affected_list, key=lambda x: x["compromise_probability"], reverse=True)
        }
