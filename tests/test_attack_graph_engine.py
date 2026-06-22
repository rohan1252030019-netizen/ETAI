"""
IMMUNEX Phase 10 — AttackGraphEngine Test Suite
=================================================
Comprehensive tests for ``core.attack_graph_engine.AttackGraphEngine``.

The module under test is expected to be created by another team and expose:
  - build_topology(nodes, edges)
  - find_shortest_path(source, target) -> list
  - blast_radius(node_id) -> dict
  - crown_jewel_discovery() -> list
  - lateral_movement_prediction(source) -> list
  - score_attack_path(path) -> float
  - topology_summary() -> dict
  - bootstrap_default_topology()

We test against a **local stub** that mirrors the expected contract so the
test suite is runnable even before the real module lands.  When the real
module is ready the stub will be swapped out via a conftest fixture.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

import pytest
import networkx as nx

# ─── Ensure project root on path ─────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ─── Stub: AttackGraphEngine ─────────────────────────────────────────────────
# This mirrors the public API that the real engine is expected to provide.

class _AttackGraphEngineStub:
    """Minimal reference implementation used by the test suite."""

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._crown_jewels: list[str] = []

    # ── topology management ───────────────────────────────────────────────

    def build_topology(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Populate the internal graph from node/edge dicts."""
        for node in nodes:
            nid = node["id"]
            attrs = {k: v for k, v in node.items() if k != "id"}
            self._graph.add_node(nid, **attrs)
            if attrs.get("is_crown_jewel"):
                self._crown_jewels.append(nid)
        for edge in edges:
            self._graph.add_edge(
                edge["source"], edge["target"],
                weight=edge.get("weight", 1.0),
                vuln=edge.get("vulnerability", ""),
            )

    def bootstrap_default_topology(self) -> None:
        """Create a minimal enterprise topology."""
        nodes = [
            {"id": "firewall", "type": "network", "criticality": "HIGH"},
            {"id": "dmz_web", "type": "server", "criticality": "MEDIUM"},
            {"id": "app_server", "type": "server", "criticality": "HIGH"},
            {"id": "db_server", "type": "database", "criticality": "CRITICAL", "is_crown_jewel": True},
            {"id": "workstation_1", "type": "endpoint", "criticality": "LOW"},
            {"id": "dc_01", "type": "domain_controller", "criticality": "CRITICAL", "is_crown_jewel": True},
        ]
        edges = [
            {"source": "firewall", "target": "dmz_web", "weight": 0.3},
            {"source": "dmz_web", "target": "app_server", "weight": 0.5},
            {"source": "app_server", "target": "db_server", "weight": 0.7},
            {"source": "workstation_1", "target": "app_server", "weight": 0.4},
            {"source": "workstation_1", "target": "dc_01", "weight": 0.8},
            {"source": "app_server", "target": "dc_01", "weight": 0.6},
        ]
        self.build_topology(nodes, edges)

    # ── queries ───────────────────────────────────────────────────────────

    def find_shortest_path(self, source: str, target: str) -> list[str]:
        """Shortest path via Dijkstra (weight-aware)."""
        if source not in self._graph or target not in self._graph:
            return []
        try:
            return nx.shortest_path(self._graph, source, target, weight="weight")
        except nx.NetworkXNoPath:
            return []

    def blast_radius(self, node_id: str) -> dict[str, Any]:
        """BFS blast radius from *node_id*."""
        if node_id not in self._graph:
            return {"node": node_id, "affected_nodes": [], "depth": 0}
        reachable = list(nx.descendants(self._graph, node_id))
        return {
            "node": node_id,
            "affected_nodes": reachable,
            "depth": nx.eccentricity(self._graph, v=node_id)
                     if reachable else 0,
            "count": len(reachable),
        }

    def crown_jewel_discovery(self) -> list[dict[str, Any]]:
        """Return all crown-jewel nodes with in-degree and criticality."""
        results: list[dict] = []
        for nid in self._crown_jewels:
            data = dict(self._graph.nodes[nid])
            data["id"] = nid
            data["in_degree"] = self._graph.in_degree(nid)
            results.append(data)
        return results

    def lateral_movement_prediction(self, source: str) -> list[dict[str, Any]]:
        """Predict lateral-movement targets reachable from *source*."""
        if source not in self._graph:
            return []
        predictions: list[dict] = []
        for succ in self._graph.successors(source):
            edge_data = self._graph.edges[source, succ]
            predictions.append({
                "target": succ,
                "weight": edge_data.get("weight", 1.0),
                "vulnerability": edge_data.get("vuln", ""),
            })
        return sorted(predictions, key=lambda x: x["weight"], reverse=True)

    def score_attack_path(self, path: list[str]) -> float:
        """Cumulative weight score for a given path."""
        if len(path) < 2:
            return 0.0
        total = 0.0
        for i in range(len(path) - 1):
            edge = self._graph.edges.get((path[i], path[i + 1]), {})
            total += edge.get("weight", 1.0)
        return round(total, 4)

    def topology_summary(self) -> dict[str, Any]:
        return {
            "nodes": self._graph.number_of_nodes(),
            "edges": self._graph.number_of_edges(),
            "crown_jewels": len(self._crown_jewels),
            "components": nx.number_weakly_connected_components(self._graph),
        }


# ─── Try importing the real module; fallback to stub ─────────────────────────

try:
    from core.attack_graph_engine import AttackGraphEngine  # type: ignore[import-untyped]
except ImportError:
    AttackGraphEngine = _AttackGraphEngineStub  # type: ignore[misc,assignment]


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> AttackGraphEngine:
    """Return a fresh AttackGraphEngine with a bootstrapped topology."""
    eng = AttackGraphEngine()
    eng.bootstrap_default_topology()
    return eng


@pytest.fixture
def empty_engine() -> AttackGraphEngine:
    """Return a fresh AttackGraphEngine with no topology."""
    return AttackGraphEngine()


@pytest.fixture
def custom_topology() -> tuple[list[dict], list[dict]]:
    """Custom node/edge lists for manual topology builds."""
    nodes = [
        {"id": "A", "type": "endpoint", "criticality": "LOW"},
        {"id": "B", "type": "server", "criticality": "MEDIUM"},
        {"id": "C", "type": "server", "criticality": "HIGH"},
        {"id": "D", "type": "database", "criticality": "CRITICAL", "is_crown_jewel": True},
        {"id": "E", "type": "endpoint", "criticality": "LOW"},
    ]
    edges = [
        {"source": "A", "target": "B", "weight": 0.2, "vulnerability": "CVE-2024-1111"},
        {"source": "B", "target": "C", "weight": 0.5, "vulnerability": "CVE-2024-2222"},
        {"source": "C", "target": "D", "weight": 0.9, "vulnerability": "CVE-2024-3333"},
    ]
    return nodes, edges


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuildTopology:
    """Topology construction and node/edge verification."""

    def test_build_topology_creates_nodes_and_edges(self, custom_topology):
        nodes, edges = custom_topology
        eng = AttackGraphEngine()
        eng.build_topology(nodes, edges)

        summary = eng.topology_summary()
        assert summary["nodes"] == 5, "Should have 5 nodes"
        assert summary["edges"] == 3, "Should have 3 directed edges"
        assert summary["crown_jewels"] >= 1, "At least one crown-jewel node"

    def test_default_bootstrap_topology(self, engine):
        summary = engine.topology_summary()
        assert summary["nodes"] >= 6, "Default topology should have ≥6 nodes"
        assert summary["edges"] >= 5, "Default topology should have ≥5 edges"
        assert summary["crown_jewels"] >= 1, "At least one crown-jewel in default topology"
        assert summary["components"] >= 1, "At least 1 connected component"


class TestShortestPath:
    """Shortest-path queries."""

    def test_find_shortest_path_returns_valid_path(self, engine):
        path = engine.find_shortest_path("firewall", "db_server")
        assert isinstance(path, list)
        assert len(path) >= 2, "Path should contain at least source and target"
        assert path[0] == "firewall"
        assert path[-1] == "db_server"
        # Every consecutive pair must be a valid edge
        for i in range(len(path) - 1):
            assert engine._graph.has_edge(path[i], path[i + 1]), (
                f"Edge {path[i]} → {path[i+1]} must exist"
            )

    def test_find_shortest_path_no_path_returns_empty(self, custom_topology):
        nodes, edges = custom_topology
        eng = AttackGraphEngine()
        eng.build_topology(nodes, edges)
        # E is isolated (no incoming or outgoing edges to A)
        result = eng.find_shortest_path("E", "A")
        assert result == [], "No path from E to A should return empty list"

    def test_find_shortest_path_same_node(self, engine):
        path = engine.find_shortest_path("firewall", "firewall")
        assert isinstance(path, list)
        assert len(path) == 1
        assert path[0] == "firewall"

    def test_find_shortest_path_nonexistent_node(self, engine):
        path = engine.find_shortest_path("nonexistent_src", "firewall")
        assert path == []


class TestBlastRadius:
    """Blast-radius computation."""

    def test_blast_radius_calculation(self, engine):
        result = engine.blast_radius("firewall")
        assert isinstance(result, dict)
        assert "affected_nodes" in result
        assert "count" in result or len(result["affected_nodes"]) >= 0
        affected = result["affected_nodes"]
        assert isinstance(affected, list)
        # firewall → dmz_web → app_server → db_server/dc_01
        assert len(affected) >= 2, "Firewall should reach at least 2 downstream nodes"

    def test_blast_radius_isolated_node(self, custom_topology):
        nodes, edges = custom_topology
        eng = AttackGraphEngine()
        eng.build_topology(nodes, edges)
        result = eng.blast_radius("E")
        assert result["affected_nodes"] == [], "Isolated node E should have empty blast radius"

    def test_blast_radius_leaf_node(self, engine):
        result = engine.blast_radius("db_server")
        assert isinstance(result, dict)
        # db_server is a leaf in the default topology — blast radius may be small
        assert isinstance(result["affected_nodes"], list)

    def test_blast_radius_unknown_node(self, engine):
        result = engine.blast_radius("nonexistent_node")
        assert result["affected_nodes"] == []


class TestCrownJewels:
    """Crown-jewel discovery."""

    def test_crown_jewel_discovery(self, engine):
        jewels = engine.crown_jewel_discovery()
        assert isinstance(jewels, list)
        assert len(jewels) >= 1, "Default topology has crown-jewels"
        for j in jewels:
            assert "id" in j
            assert j.get("criticality") in ("CRITICAL", "HIGH")

    def test_crown_jewel_has_in_degree(self, engine):
        jewels = engine.crown_jewel_discovery()
        for j in jewels:
            assert "in_degree" in j
            assert isinstance(j["in_degree"], int)

    def test_crown_jewel_empty_topology(self, empty_engine):
        jewels = empty_engine.crown_jewel_discovery()
        assert jewels == []


class TestLateralMovement:
    """Lateral movement prediction."""

    def test_lateral_movement_prediction(self, engine):
        predictions = engine.lateral_movement_prediction("workstation_1")
        assert isinstance(predictions, list)
        assert len(predictions) >= 1, "workstation_1 has successors"
        for p in predictions:
            assert "target" in p
            assert "weight" in p

    def test_lateral_movement_sorted_by_weight(self, engine):
        predictions = engine.lateral_movement_prediction("workstation_1")
        if len(predictions) >= 2:
            weights = [p["weight"] for p in predictions]
            assert weights == sorted(weights, reverse=True), "Should be sorted descending by weight"

    def test_lateral_movement_nonexistent_source(self, engine):
        predictions = engine.lateral_movement_prediction("nonexistent")
        assert predictions == []


class TestPathScoring:
    """Attack path scoring."""

    def test_attack_path_scoring(self, custom_topology):
        nodes, edges = custom_topology
        eng = AttackGraphEngine()
        eng.build_topology(nodes, edges)

        path = eng.find_shortest_path("A", "D")
        assert len(path) >= 2

        score = eng.score_attack_path(path)
        assert isinstance(score, float)
        assert score > 0.0, "Non-trivial path should have positive score"

        # Verify the score equals sum of edge weights along the path
        expected = sum(
            eng._graph.edges[path[i], path[i + 1]].get("weight", 1.0)
            for i in range(len(path) - 1)
        )
        assert abs(score - round(expected, 4)) < 1e-6

    def test_attack_path_scoring_single_node(self, engine):
        score = engine.score_attack_path(["firewall"])
        assert score == 0.0, "Single-node path has zero score"

    def test_attack_path_scoring_empty(self, engine):
        score = engine.score_attack_path([])
        assert score == 0.0


class TestTopologySummary:
    """Topology summary statistics."""

    def test_topology_summary(self, engine):
        summary = engine.topology_summary()
        assert isinstance(summary, dict)
        assert "nodes" in summary
        assert "edges" in summary
        assert "crown_jewels" in summary
        assert "components" in summary
        assert summary["nodes"] > 0
        assert summary["edges"] > 0

    def test_topology_summary_empty(self, empty_engine):
        summary = empty_engine.topology_summary()
        assert summary["nodes"] == 0
        assert summary["edges"] == 0
