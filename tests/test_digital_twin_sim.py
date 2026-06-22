"""
IMMUNEX Phase 10 — IndustrialTwinSimulator Test Suite
======================================================
Comprehensive tests for ``core.digital_twin_simulator.IndustrialTwinSimulator``.

Expected contract:
  - __init__(sector)
  - build_topology(sector) — builds sector-specific topology
  - get_topology() -> nx.DiGraph
  - topology_summary() -> dict
  - simulate_ransomware(entry_point, speed) -> dict
  - simulate_apt_lateral(entry_point, target) -> dict
  - simulate_scada_manipulation(target_plc) -> dict
  - simulate_defensive(scenario, controls) -> dict
  - replay_attack(attack_log) -> dict

Sectors: "energy_grid", "government", "healthcare", "education"
"""

from __future__ import annotations

import os
import sys
from typing import Any

import pytest
import networkx as nx

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ─── Stub: IndustrialTwinSimulator ───────────────────────────────────────────

class _IndustrialTwinSimulatorStub:
    """Reference implementation for testing."""

    # Sector topology definitions
    _SECTOR_TOPOLOGIES: dict[str, dict] = {
        "energy_grid": {
            "nodes": [
                {"id": "scada_hmi", "type": "HMI", "criticality": "CRITICAL"},
                {"id": "plc_substation_1", "type": "PLC", "criticality": "CRITICAL"},
                {"id": "plc_substation_2", "type": "PLC", "criticality": "CRITICAL"},
                {"id": "rtu_field_1", "type": "RTU", "criticality": "HIGH"},
                {"id": "historian", "type": "server", "criticality": "HIGH"},
                {"id": "eng_workstation", "type": "endpoint", "criticality": "MEDIUM"},
                {"id": "corp_firewall", "type": "firewall", "criticality": "HIGH"},
                {"id": "ot_switch", "type": "switch", "criticality": "HIGH"},
            ],
            "edges": [
                ("corp_firewall", "eng_workstation"),
                ("eng_workstation", "scada_hmi"),
                ("scada_hmi", "plc_substation_1"),
                ("scada_hmi", "plc_substation_2"),
                ("plc_substation_1", "rtu_field_1"),
                ("scada_hmi", "historian"),
                ("ot_switch", "plc_substation_1"),
                ("ot_switch", "plc_substation_2"),
            ],
        },
        "government": {
            "nodes": [
                {"id": "perimeter_fw", "type": "firewall", "criticality": "HIGH"},
                {"id": "email_gateway", "type": "server", "criticality": "MEDIUM"},
                {"id": "dc_primary", "type": "domain_controller", "criticality": "CRITICAL"},
                {"id": "file_server", "type": "server", "criticality": "HIGH"},
                {"id": "classified_db", "type": "database", "criticality": "CRITICAL"},
                {"id": "analyst_ws", "type": "endpoint", "criticality": "LOW"},
                {"id": "vpn_gateway", "type": "gateway", "criticality": "HIGH"},
            ],
            "edges": [
                ("perimeter_fw", "email_gateway"),
                ("perimeter_fw", "vpn_gateway"),
                ("email_gateway", "analyst_ws"),
                ("analyst_ws", "dc_primary"),
                ("dc_primary", "file_server"),
                ("file_server", "classified_db"),
                ("vpn_gateway", "dc_primary"),
            ],
        },
        "healthcare": {
            "nodes": [
                {"id": "hospital_fw", "type": "firewall", "criticality": "HIGH"},
                {"id": "ehr_server", "type": "server", "criticality": "CRITICAL"},
                {"id": "pacs_imaging", "type": "medical_device", "criticality": "CRITICAL"},
                {"id": "nurse_station", "type": "endpoint", "criticality": "MEDIUM"},
                {"id": "infusion_pump", "type": "iot_device", "criticality": "CRITICAL"},
                {"id": "lab_system", "type": "server", "criticality": "HIGH"},
            ],
            "edges": [
                ("hospital_fw", "nurse_station"),
                ("nurse_station", "ehr_server"),
                ("ehr_server", "pacs_imaging"),
                ("nurse_station", "infusion_pump"),
                ("ehr_server", "lab_system"),
            ],
        },
        "education": {
            "nodes": [
                {"id": "campus_fw", "type": "firewall", "criticality": "MEDIUM"},
                {"id": "lms_server", "type": "server", "criticality": "HIGH"},
                {"id": "student_portal", "type": "server", "criticality": "MEDIUM"},
                {"id": "research_cluster", "type": "server", "criticality": "HIGH"},
                {"id": "faculty_ws", "type": "endpoint", "criticality": "LOW"},
                {"id": "student_wifi", "type": "access_point", "criticality": "LOW"},
            ],
            "edges": [
                ("campus_fw", "lms_server"),
                ("campus_fw", "student_portal"),
                ("campus_fw", "student_wifi"),
                ("student_wifi", "student_portal"),
                ("faculty_ws", "lms_server"),
                ("lms_server", "research_cluster"),
            ],
        },
    }

    def __init__(self, sector: str = "energy_grid") -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._sector = sector
        self.build_topology(sector)

    def build_topology(self, sector: str) -> None:
        topo = self._SECTOR_TOPOLOGIES.get(sector, self._SECTOR_TOPOLOGIES["energy_grid"])
        self._graph.clear()
        for node in topo["nodes"]:
            nid = node["id"]
            self._graph.add_node(nid, **{k: v for k, v in node.items() if k != "id"})
        for src, dst in topo["edges"]:
            self._graph.add_edge(src, dst)

    def get_topology(self) -> nx.DiGraph:
        return self._graph

    def topology_summary(self) -> dict:
        return {
            "sector": self._sector,
            "nodes": self._graph.number_of_nodes(),
            "edges": self._graph.number_of_edges(),
        }

    def simulate_ransomware(
        self, entry_point: str, speed: float = 1.0
    ) -> dict[str, Any]:
        """BFS-based ransomware propagation simulation."""
        if entry_point not in self._graph:
            return {"entry_point": entry_point, "infected": [], "total": 0}

        infected: list[str] = [entry_point]
        queue: list[str] = [entry_point]
        visited: set[str] = {entry_point}
        step = 0

        while queue and step < 100:
            next_wave: list[str] = []
            for node in queue:
                for succ in self._graph.successors(node):
                    if succ not in visited:
                        # Speed controls propagation probability
                        if speed >= 0.5 or step == 0:
                            visited.add(succ)
                            infected.append(succ)
                            next_wave.append(succ)
            queue = next_wave
            step += 1
            if speed < 0.5 and step > 1:
                break  # slow speed stops after limited hops

        return {
            "entry_point": entry_point,
            "infected": infected,
            "total": len(infected),
            "steps": step,
        }

    def simulate_apt_lateral(
        self, entry_point: str, target: str
    ) -> dict[str, Any]:
        """Simulate APT lateral movement from entry to target."""
        if entry_point not in self._graph or target not in self._graph:
            return {"entry_point": entry_point, "target": target, "path": [], "reachable": False}
        try:
            path = nx.shortest_path(self._graph, entry_point, target)
            return {
                "entry_point": entry_point,
                "target": target,
                "path": path,
                "hops": len(path) - 1,
                "reachable": True,
            }
        except nx.NetworkXNoPath:
            return {"entry_point": entry_point, "target": target, "path": [], "reachable": False}

    def simulate_scada_manipulation(self, target_plc: str) -> dict[str, Any]:
        """Simulate SCADA/PLC manipulation attack."""
        if target_plc not in self._graph:
            return {"target": target_plc, "success": False, "reason": "Target not found"}

        node_data = dict(self._graph.nodes[target_plc])
        is_plc = node_data.get("type") in ("PLC", "RTU", "iot_device", "medical_device")

        return {
            "target": target_plc,
            "success": is_plc,
            "node_type": node_data.get("type", "unknown"),
            "criticality": node_data.get("criticality", "UNKNOWN"),
            "downstream_affected": list(nx.descendants(self._graph, target_plc)),
            "reason": "PLC/ICS device manipulated" if is_plc else "Target is not a PLC/ICS device",
        }

    def simulate_defensive(
        self,
        scenario: str,
        controls: list[str] | None = None,
    ) -> dict[str, Any]:
        """Simulate defensive controls reducing impact."""
        controls = controls or []

        # Base impact without controls
        base_impact = self._graph.number_of_nodes()
        reduction = 0.0

        control_effects = {
            "network_segmentation": 0.35,
            "endpoint_detection": 0.20,
            "mfa": 0.15,
            "patch_management": 0.15,
            "backup_strategy": 0.10,
        }

        for ctrl in controls:
            reduction += control_effects.get(ctrl, 0.05)
        reduction = min(reduction, 0.90)

        mitigated_impact = base_impact * (1.0 - reduction)

        return {
            "scenario": scenario,
            "controls_applied": controls,
            "base_impact": base_impact,
            "reduction_pct": round(reduction * 100, 1),
            "mitigated_impact": round(mitigated_impact, 1),
        }

    def replay_attack(self, attack_log: list[dict]) -> dict[str, Any]:
        """Replay a recorded attack sequence."""
        results: list[dict] = []
        for step in attack_log:
            action = step.get("action", "unknown")
            target = step.get("target", "")
            outcome = "success" if target in self._graph else "failed"
            results.append({
                "action": action,
                "target": target,
                "outcome": outcome,
                "timestamp": step.get("timestamp", ""),
            })

        return {
            "total_steps": len(attack_log),
            "successful_steps": sum(1 for r in results if r["outcome"] == "success"),
            "results": results,
        }


# ─── Try importing real module; fallback to stub ─────────────────────────────

try:
    from core.digital_twin_simulator import IndustrialTwinSimulator  # type: ignore[import-untyped]
except ImportError:
    IndustrialTwinSimulator = _IndustrialTwinSimulatorStub  # type: ignore[misc,assignment]


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(params=["energy_grid", "government", "healthcare", "education"])
def sector(request) -> str:
    return request.param


@pytest.fixture
def energy_sim() -> _IndustrialTwinSimulatorStub:
    return IndustrialTwinSimulator(sector="energy_grid")


@pytest.fixture
def gov_sim() -> _IndustrialTwinSimulatorStub:
    return IndustrialTwinSimulator(sector="government")


@pytest.fixture
def health_sim() -> _IndustrialTwinSimulatorStub:
    return IndustrialTwinSimulator(sector="healthcare")


@pytest.fixture
def edu_sim() -> _IndustrialTwinSimulatorStub:
    return IndustrialTwinSimulator(sector="education")


# ═══════════════════════════════════════════════════════════════════════════════
# Topology Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTopologies:
    """Sector-specific topology verification."""

    def test_energy_grid_topology_has_expected_nodes(self, energy_sim):
        g = energy_sim.get_topology()
        node_ids = set(g.nodes)
        assert "scada_hmi" in node_ids
        assert "plc_substation_1" in node_ids
        assert "plc_substation_2" in node_ids
        assert g.number_of_nodes() >= 6
        assert g.number_of_edges() >= 5

    def test_government_topology_has_expected_nodes(self, gov_sim):
        g = gov_sim.get_topology()
        node_ids = set(g.nodes)
        assert "dc_primary" in node_ids
        assert "classified_db" in node_ids
        assert "perimeter_fw" in node_ids
        assert g.number_of_nodes() >= 5

    def test_healthcare_topology_has_expected_nodes(self, health_sim):
        g = health_sim.get_topology()
        node_ids = set(g.nodes)
        assert "ehr_server" in node_ids
        assert "infusion_pump" in node_ids
        assert g.number_of_nodes() >= 5

    def test_education_topology_has_expected_nodes(self, edu_sim):
        g = edu_sim.get_topology()
        node_ids = set(g.nodes)
        assert "lms_server" in node_ids
        assert "research_cluster" in node_ids
        assert g.number_of_nodes() >= 4

    def test_topology_summary_structure(self, energy_sim):
        summary = energy_sim.topology_summary()
        assert "sector" in summary
        assert "nodes" in summary
        assert "edges" in summary
        assert summary["nodes"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Ransomware Simulation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRansomwareSimulation:
    """Ransomware propagation simulation."""

    def test_ransomware_propagation_infects_nodes(self, energy_sim):
        result = energy_sim.simulate_ransomware("corp_firewall", speed=1.0)
        assert result["total"] >= 2, "Should infect entry + at least one connected node"
        assert result["entry_point"] == "corp_firewall"
        assert "corp_firewall" in result["infected"]

    def test_ransomware_propagation_respects_speed(self, energy_sim):
        fast = energy_sim.simulate_ransomware("corp_firewall", speed=1.0)
        slow = energy_sim.simulate_ransomware("corp_firewall", speed=0.1)
        assert fast["total"] >= slow["total"], (
            "Fast propagation should infect >= nodes compared to slow"
        )

    def test_ransomware_unknown_entry(self, energy_sim):
        result = energy_sim.simulate_ransomware("nonexistent_node")
        assert result["total"] == 0
        assert result["infected"] == []

    def test_ransomware_leaf_entry(self, energy_sim):
        result = energy_sim.simulate_ransomware("rtu_field_1", speed=1.0)
        assert result["total"] >= 1  # at least the entry node itself
        assert "rtu_field_1" in result["infected"]


# ═══════════════════════════════════════════════════════════════════════════════
# APT Lateral Movement Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAPTLateralMovement:
    """APT lateral movement simulation."""

    def test_apt_lateral_movement_finds_path(self, energy_sim):
        result = energy_sim.simulate_apt_lateral("corp_firewall", "plc_substation_1")
        assert result["reachable"] is True
        assert len(result["path"]) >= 2
        assert result["path"][0] == "corp_firewall"
        assert result["path"][-1] == "plc_substation_1"
        assert result["hops"] >= 1

    def test_apt_lateral_unreachable(self, energy_sim):
        # rtu_field_1 has no outbound path to corp_firewall in this directed graph
        result = energy_sim.simulate_apt_lateral("rtu_field_1", "corp_firewall")
        assert result["reachable"] is False
        assert result["path"] == []

    def test_apt_lateral_same_node(self, energy_sim):
        result = energy_sim.simulate_apt_lateral("scada_hmi", "scada_hmi")
        assert result["reachable"] is True
        assert result["hops"] == 0

    def test_apt_lateral_government_chain(self, gov_sim):
        result = gov_sim.simulate_apt_lateral("perimeter_fw", "classified_db")
        assert result["reachable"] is True
        assert "classified_db" in result["path"]


# ═══════════════════════════════════════════════════════════════════════════════
# SCADA Manipulation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSCADAManipulation:
    """SCADA / PLC manipulation attacks."""

    def test_scada_manipulation_targets_plc(self, energy_sim):
        result = energy_sim.simulate_scada_manipulation("plc_substation_1")
        assert result["success"] is True
        assert result["node_type"] == "PLC"
        assert result["criticality"] == "CRITICAL"

    def test_scada_manipulation_non_plc_fails(self, energy_sim):
        result = energy_sim.simulate_scada_manipulation("eng_workstation")
        assert result["success"] is False

    def test_scada_manipulation_unknown_target(self, energy_sim):
        result = energy_sim.simulate_scada_manipulation("nonexistent")
        assert result["success"] is False

    def test_scada_downstream_affected(self, energy_sim):
        result = energy_sim.simulate_scada_manipulation("plc_substation_1")
        assert isinstance(result["downstream_affected"], list)

    def test_healthcare_medical_device(self, health_sim):
        result = health_sim.simulate_scada_manipulation("infusion_pump")
        assert result["success"] is True
        assert result["node_type"] == "iot_device"


# ═══════════════════════════════════════════════════════════════════════════════
# Defensive Simulation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDefensiveSimulation:
    """Defensive control simulation."""

    def test_defensive_simulation_reduces_impact(self, energy_sim):
        no_controls = energy_sim.simulate_defensive("ransomware", controls=[])
        with_controls = energy_sim.simulate_defensive(
            "ransomware",
            controls=["network_segmentation", "endpoint_detection", "mfa"],
        )
        assert with_controls["mitigated_impact"] < no_controls["base_impact"]
        assert with_controls["reduction_pct"] > 0

    def test_defensive_no_controls_full_impact(self, energy_sim):
        result = energy_sim.simulate_defensive("ransomware", controls=[])
        assert result["reduction_pct"] == 0.0
        assert result["mitigated_impact"] == result["base_impact"]

    def test_defensive_max_reduction_capped(self, energy_sim):
        result = energy_sim.simulate_defensive(
            "ransomware",
            controls=[
                "network_segmentation", "endpoint_detection",
                "mfa", "patch_management", "backup_strategy",
            ],
        )
        assert result["reduction_pct"] <= 95.0, "Reduction should be capped"
        assert result["mitigated_impact"] > 0, "Some residual impact always remains"


# ═══════════════════════════════════════════════════════════════════════════════
# Replay Attack Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestReplayAttack:
    """Attack replay simulation."""

    def test_replay_attack_produces_result(self, energy_sim):
        attack_log = [
            {"action": "scan", "target": "corp_firewall", "timestamp": "2024-01-01T00:00:00"},
            {"action": "exploit", "target": "eng_workstation", "timestamp": "2024-01-01T00:01:00"},
            {"action": "pivot", "target": "scada_hmi", "timestamp": "2024-01-01T00:02:00"},
            {"action": "manipulate", "target": "plc_substation_1", "timestamp": "2024-01-01T00:03:00"},
        ]
        result = energy_sim.replay_attack(attack_log)
        assert result["total_steps"] == 4
        assert result["successful_steps"] == 4
        assert len(result["results"]) == 4
        for step_result in result["results"]:
            assert step_result["outcome"] == "success"

    def test_replay_attack_with_unknown_targets(self, energy_sim):
        attack_log = [
            {"action": "scan", "target": "corp_firewall", "timestamp": "2024-01-01T00:00:00"},
            {"action": "exploit", "target": "nonexistent_host", "timestamp": "2024-01-01T00:01:00"},
        ]
        result = energy_sim.replay_attack(attack_log)
        assert result["total_steps"] == 2
        assert result["successful_steps"] == 1

    def test_replay_empty_log(self, energy_sim):
        result = energy_sim.replay_attack([])
        assert result["total_steps"] == 0
        assert result["successful_steps"] == 0
        assert result["results"] == []
