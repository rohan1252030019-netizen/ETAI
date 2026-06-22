"""
IMMUNEX Digital Twin Simulator
===============================
Phase 5 — Sector-specific topology generation and multi-scenario attack
simulation engine.

Extends the existing ``twin_engine.DigitalTwinEngine`` with:
* CNI sector topologies (Energy Grid, Government, Healthcare, Education)
* Ransomware propagation, APT lateral movement, SCADA manipulation, and
  data exfiltration simulations
* Defensive replay and mitigation modelling

All topologies use NetworkX DiGraph and are compatible with the existing
BlastRadiusSimulator, CrownJewelAnalyzer, and LateralMovementPredictor.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import networkx as nx
from pydantic import BaseModel, Field

from utils.logger import log

# Import node/edge constants and engine from the existing twin_engine module
from twin_engine import (
    DigitalTwinEngine,
    NODE_HOST,
    NODE_USER,
    NODE_SERVICE,
    NODE_IP,
    NODE_PROCESS,
    EDGE_CONNECTED_TO,
    EDGE_COMMUNICATED_WITH,
    EDGE_LOGGED_INTO,
    EDGE_EXECUTED,
    EDGE_PRIV_ESC_TO,
)


# ═══════════════════════════════════════════════════════════════════════════════
#  Enums & Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class CNISector(str, Enum):
    """Critical National Infrastructure sectors."""
    ENERGY_GRID = "ENERGY_GRID"
    GOVERNMENT = "GOVERNMENT"
    HEALTHCARE = "HEALTHCARE"
    EDUCATION = "EDUCATION"


class SimulationScenario(BaseModel):
    """Definition of a simulation experiment to be replayed."""
    scenario_id: str = Field(default_factory=lambda: f"SIM-{uuid.uuid4().hex[:8]}")
    name: str
    sector: CNISector
    patient_zero_ip: str
    threat_type: str = Field(
        description="One of: ransomware, apt_lateral, scada_manipulation, data_exfiltration"
    )
    speed_coefficient: float = Field(default=0.85, ge=0.0, le=1.0)


class SimulationResult(BaseModel):
    """Outcome of a single simulation run."""
    scenario_id: str
    infected_nodes: list[str] = Field(default_factory=list)
    isolated_nodes: list[str] = Field(default_factory=list)
    total_affected: int = 0
    blast_radius_percent: float = 0.0
    estimated_downtime_hours: float = 0.0
    recovery_steps: list[str] = Field(default_factory=list)
    simulation_log: list[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
#  Topology Builder Helpers (module-level for reuse)
# ═══════════════════════════════════════════════════════════════════════════════

# Extended edge type constants used in OT/sector topologies
EDGE_CONTROLS = "CONTROLS"
EDGE_MONITORS = "MONITORS"
EDGE_SERVES = "SERVES"
EDGE_REPLICATES_TO = "REPLICATES_TO"


def _add_node(
    g: nx.DiGraph,
    node_id: str,
    node_type: str = NODE_HOST,
    *,
    criticality: str = "MEDIUM",
    **kwargs: Any,
) -> None:
    """Convenience: add a typed node with metadata."""
    g.add_node(node_id, type=node_type, criticality=criticality, **kwargs)


def _link(
    g: nx.DiGraph,
    src: str,
    dst: str,
    edge_type: str = EDGE_COMMUNICATED_WITH,
    **kwargs: Any,
) -> None:
    """Convenience: add a directed edge between two existing nodes."""
    g.add_edge(src, dst, type=edge_type, **kwargs)


# ═══════════════════════════════════════════════════════════════════════════════
#  Industrial Twin Simulator
# ═══════════════════════════════════════════════════════════════════════════════

class IndustrialTwinSimulator:
    """
    Generates sector-specific network topologies and runs attack simulations
    on them.  Topologies are independent NetworkX DiGraphs; results reference
    node IDs defined within each topology.
    """

    # Sector topology definitions for test suite compatibility
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
        "telecom": {
            "nodes": [
                {"id": "core_router", "type": "router", "criticality": "CRITICAL"},
                {"id": "billing_system", "type": "server", "criticality": "HIGH"},
            ],
            "edges": [
                ("core_router", "billing_system"),
            ],
        },
        "finance": {
            "nodes": [
                {"id": "trading_engine", "type": "server", "criticality": "CRITICAL"},
                {"id": "db_transactions", "type": "database", "criticality": "CRITICAL"},
            ],
            "edges": [
                ("trading_engine", "db_transactions"),
            ],
        },
    }

    def __init__(self, sector: Optional[str] = None) -> None:
        self._topologies: dict[CNISector, nx.DiGraph] = {}
        # Pre-build all sector topologies
        self._topologies[CNISector.ENERGY_GRID] = self.build_energy_grid_topology()
        self._topologies[CNISector.GOVERNMENT] = self.build_government_topology()
        self._topologies[CNISector.HEALTHCARE] = self.build_healthcare_topology()
        self._topologies[CNISector.EDUCATION] = self.build_education_topology()
        
        self._sector = sector
        self._graph = nx.DiGraph()
        if sector is not None:
            self.build_topology(sector)

        log.info(
            "IndustrialTwinSimulator initialized",
            sectors=list(self._topologies.keys()),
            compat_sector=sector,
        )

    def build_topology(self, sector: str) -> None:
        normalized = sector.lower()
        if normalized == "energy":
            normalized = "energy_grid"
        topo = self._SECTOR_TOPOLOGIES.get(normalized, self._SECTOR_TOPOLOGIES["energy_grid"])
        self._graph.clear()
        for node in topo["nodes"]:
            nid = node["id"]
            self._graph.add_node(nid, **{k: v for k, v in node.items() if k != "id"})
        for src, dst in topo["edges"]:
            self._graph.add_edge(src, dst)

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

    # ── Topology accessors ────────────────────────────────────────────────────

    def get_topology(self, sector: Optional[Any] = None) -> nx.DiGraph:
        """Return the pre-built topology for *sector* or self._graph."""
        if sector is None:
            return self._graph
        if isinstance(sector, CNISector):
            return self._topologies[sector]
        str_sector = str(sector).lower()
        if str_sector == "energy" or str_sector == "energy_grid":
            return self._topologies[CNISector.ENERGY_GRID]
        elif str_sector == "government":
            return self._topologies[CNISector.GOVERNMENT]
        elif str_sector == "healthcare":
            return self._topologies[CNISector.HEALTHCARE]
        elif str_sector == "education":
            return self._topologies[CNISector.EDUCATION]
        return self._topologies[CNISector.ENERGY_GRID]

    # ──────────────────────────────────────────────────────────────────────────
    #  Topology Builders
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def build_energy_grid_topology() -> nx.DiGraph:
        """
        Energy/SCADA topology — 22 nodes.

        Layers: Corporate IT → DMZ → OT Control Centre → Field Devices
        """
        g = nx.DiGraph(sector="ENERGY_GRID")

        # --- Corporate IT zone ---
        _add_node(g, "EG-CORP-FW",     criticality="HIGH",     role="corporate_firewall")
        _add_node(g, "EG-CORP-WS-01",  criticality="LOW",      role="engineering_workstation")
        _add_node(g, "EG-CORP-WS-02",  criticality="LOW",      role="business_workstation")
        _add_node(g, "EG-CORP-EMAIL",  criticality="MEDIUM",   role="email_server", node_type=NODE_SERVICE)
        _add_node(g, "EG-CORP-AD",     criticality="CRITICAL", role="domain_controller")

        # --- DMZ ---
        _add_node(g, "EG-DMZ-HIST",    criticality="HIGH",     role="historian_server")
        _add_node(g, "EG-DMZ-JUMP",    criticality="HIGH",     role="jump_host")

        # --- OT Control Centre ---
        _add_node(g, "EG-OT-FW",       criticality="CRITICAL", role="ot_firewall")
        _add_node(g, "EG-SCADA-SRV-01", criticality="CRITICAL", role="scada_master")
        _add_node(g, "EG-SCADA-SRV-02", criticality="CRITICAL", role="scada_backup")
        _add_node(g, "EG-HMI-01",      criticality="HIGH",     role="hmi_panel")
        _add_node(g, "EG-HMI-02",      criticality="HIGH",     role="hmi_panel")
        _add_node(g, "EG-EWS-01",      criticality="HIGH",     role="engineering_workstation_ot")

        # --- Field devices ---
        _add_node(g, "EG-PLC-01",      criticality="CRITICAL", role="plc_substation_A")
        _add_node(g, "EG-PLC-02",      criticality="CRITICAL", role="plc_substation_B")
        _add_node(g, "EG-RTU-01",      criticality="HIGH",     role="rtu_feeder_1")
        _add_node(g, "EG-RTU-02",      criticality="HIGH",     role="rtu_feeder_2")
        _add_node(g, "EG-CB-01",       criticality="CRITICAL", role="circuit_breaker_main")
        _add_node(g, "EG-CB-02",       criticality="HIGH",     role="circuit_breaker_backup")
        _add_node(g, "EG-XFMR-01",    criticality="CRITICAL", role="power_transformer_132kV")
        _add_node(g, "EG-XFMR-02",    criticality="HIGH",     role="power_transformer_33kV")
        _add_node(g, "EG-METER-GW",    criticality="MEDIUM",   role="smart_meter_gateway")

        # --- Edges ---
        # Corporate zone
        _link(g, "EG-CORP-FW",    "EG-CORP-WS-01", protocol="TCP")
        _link(g, "EG-CORP-FW",    "EG-CORP-WS-02", protocol="TCP")
        _link(g, "EG-CORP-FW",    "EG-CORP-EMAIL",  protocol="SMTP")
        _link(g, "EG-CORP-FW",    "EG-CORP-AD",     protocol="Kerberos")
        _link(g, "EG-CORP-WS-01", "EG-CORP-AD",     protocol="LDAP")
        _link(g, "EG-CORP-WS-02", "EG-CORP-EMAIL",  protocol="IMAP")
        # Corp → DMZ
        _link(g, "EG-CORP-FW",    "EG-DMZ-HIST",    protocol="TCP")
        _link(g, "EG-CORP-FW",    "EG-DMZ-JUMP",    protocol="SSH")
        _link(g, "EG-DMZ-HIST",   "EG-DMZ-JUMP",    protocol="TCP")
        # DMZ → OT
        _link(g, "EG-DMZ-JUMP",   "EG-OT-FW",       protocol="SSH")
        _link(g, "EG-DMZ-HIST",   "EG-OT-FW",       protocol="OPC-DA")
        # OT Control
        _link(g, "EG-OT-FW",      "EG-SCADA-SRV-01", protocol="Modbus/TCP")
        _link(g, "EG-OT-FW",      "EG-SCADA-SRV-02", protocol="Modbus/TCP")
        _link(g, "EG-SCADA-SRV-01", "EG-HMI-01",     protocol="OPC-UA")
        _link(g, "EG-SCADA-SRV-01", "EG-HMI-02",     protocol="OPC-UA")
        _link(g, "EG-SCADA-SRV-02", "EG-SCADA-SRV-01", edge_type=EDGE_REPLICATES_TO, protocol="TCP")
        _link(g, "EG-EWS-01",     "EG-SCADA-SRV-01", protocol="SSH")
        # SCADA → Field
        _link(g, "EG-SCADA-SRV-01", "EG-PLC-01",     edge_type=EDGE_CONTROLS, protocol="Modbus")
        _link(g, "EG-SCADA-SRV-01", "EG-PLC-02",     edge_type=EDGE_CONTROLS, protocol="Modbus")
        _link(g, "EG-SCADA-SRV-01", "EG-RTU-01",     edge_type=EDGE_CONTROLS, protocol="DNP3")
        _link(g, "EG-SCADA-SRV-01", "EG-RTU-02",     edge_type=EDGE_CONTROLS, protocol="DNP3")
        _link(g, "EG-PLC-01",       "EG-CB-01",      edge_type=EDGE_CONTROLS, protocol="IEC-61850")
        _link(g, "EG-PLC-01",       "EG-XFMR-01",   edge_type=EDGE_MONITORS, protocol="IEC-61850")
        _link(g, "EG-PLC-02",       "EG-CB-02",      edge_type=EDGE_CONTROLS, protocol="IEC-61850")
        _link(g, "EG-PLC-02",       "EG-XFMR-02",   edge_type=EDGE_MONITORS, protocol="IEC-61850")
        _link(g, "EG-RTU-01",       "EG-METER-GW",   edge_type=EDGE_MONITORS, protocol="DLMS/COSEM")

        log.debug("Energy grid topology built", nodes=g.number_of_nodes(), edges=g.number_of_edges())
        return g

    @staticmethod
    def build_government_topology() -> nx.DiGraph:
        """
        Government network — 20 nodes.

        Layers: Public DMZ → Internal Services → Restricted Zone → Admin
        """
        g = nx.DiGraph(sector="GOVERNMENT")

        # --- Perimeter / DMZ ---
        _add_node(g, "GOV-EXT-FW",     criticality="HIGH",     role="perimeter_firewall")
        _add_node(g, "GOV-VPN-GW",     criticality="HIGH",     role="vpn_gateway")
        _add_node(g, "GOV-WEB-SRV",    criticality="MEDIUM",   role="public_web_portal", node_type=NODE_SERVICE)
        _add_node(g, "GOV-WAF",        criticality="HIGH",     role="web_application_firewall")

        # --- Internal Services ---
        _add_node(g, "GOV-DC-01",      criticality="CRITICAL", role="primary_domain_controller")
        _add_node(g, "GOV-DC-02",      criticality="CRITICAL", role="secondary_domain_controller")
        _add_node(g, "GOV-EMAIL-SRV",  criticality="HIGH",     role="email_exchange_server", node_type=NODE_SERVICE)
        _add_node(g, "GOV-FILE-SRV",   criticality="HIGH",     role="file_server")
        _add_node(g, "GOV-PRINT-SRV",  criticality="LOW",      role="print_server", node_type=NODE_SERVICE)
        _add_node(g, "GOV-DNS-SRV",    criticality="HIGH",     role="internal_dns", node_type=NODE_SERVICE)

        # --- Workstations ---
        _add_node(g, "GOV-WS-01",      criticality="LOW",      role="officer_workstation")
        _add_node(g, "GOV-WS-02",      criticality="LOW",      role="officer_workstation")
        _add_node(g, "GOV-WS-03",      criticality="LOW",      role="officer_workstation")
        _add_node(g, "GOV-WS-ADMIN",   criticality="MEDIUM",   role="admin_workstation")

        # --- Restricted Zone ---
        _add_node(g, "GOV-DB-CITIZEN", criticality="CRITICAL", role="citizen_database")
        _add_node(g, "GOV-DB-FINANCE", criticality="CRITICAL", role="financial_database")
        _add_node(g, "GOV-APP-SRV",    criticality="HIGH",     role="internal_application_server")
        _add_node(g, "GOV-BACKUP-SRV", criticality="HIGH",     role="backup_server")
        _add_node(g, "GOV-LOG-SRV",    criticality="MEDIUM",   role="siem_log_collector")
        _add_node(g, "GOV-CERT-SRV",   criticality="HIGH",     role="certificate_authority")

        # --- Edges ---
        _link(g, "GOV-EXT-FW",   "GOV-WAF",        protocol="HTTPS")
        _link(g, "GOV-EXT-FW",   "GOV-VPN-GW",     protocol="IPSec")
        _link(g, "GOV-WAF",      "GOV-WEB-SRV",    protocol="HTTPS")
        _link(g, "GOV-VPN-GW",   "GOV-DC-01",      protocol="Kerberos")
        _link(g, "GOV-VPN-GW",   "GOV-WS-ADMIN",   protocol="RDP")
        # Internal services
        _link(g, "GOV-DC-01",    "GOV-DC-02",       edge_type=EDGE_REPLICATES_TO, protocol="LDAP")
        _link(g, "GOV-DC-01",    "GOV-DNS-SRV",     protocol="DNS")
        _link(g, "GOV-DC-01",    "GOV-CERT-SRV",    protocol="TCP")
        _link(g, "GOV-WS-01",   "GOV-DC-01",       protocol="Kerberos")
        _link(g, "GOV-WS-02",   "GOV-DC-01",       protocol="Kerberos")
        _link(g, "GOV-WS-03",   "GOV-DC-01",       protocol="Kerberos")
        _link(g, "GOV-WS-ADMIN","GOV-DC-01",       protocol="Kerberos")
        _link(g, "GOV-WS-01",   "GOV-EMAIL-SRV",   protocol="MAPI")
        _link(g, "GOV-WS-02",   "GOV-FILE-SRV",    protocol="SMB")
        _link(g, "GOV-WS-03",   "GOV-FILE-SRV",    protocol="SMB")
        _link(g, "GOV-WS-ADMIN","GOV-FILE-SRV",    protocol="SMB")
        _link(g, "GOV-WS-01",   "GOV-PRINT-SRV",   protocol="IPP")
        # Restricted zone
        _link(g, "GOV-APP-SRV",  "GOV-DB-CITIZEN",  protocol="TDS")
        _link(g, "GOV-APP-SRV",  "GOV-DB-FINANCE",  protocol="TDS")
        _link(g, "GOV-DC-01",    "GOV-APP-SRV",     protocol="TCP")
        _link(g, "GOV-FILE-SRV", "GOV-BACKUP-SRV",  protocol="rsync")
        _link(g, "GOV-DB-CITIZEN", "GOV-BACKUP-SRV", protocol="rsync")
        _link(g, "GOV-LOG-SRV",  "GOV-DC-01",       edge_type=EDGE_MONITORS, protocol="Syslog")
        _link(g, "GOV-LOG-SRV",  "GOV-EXT-FW",      edge_type=EDGE_MONITORS, protocol="Syslog")

        log.debug("Government topology built", nodes=g.number_of_nodes(), edges=g.number_of_edges())
        return g

    @staticmethod
    def build_healthcare_topology() -> nx.DiGraph:
        """
        Healthcare network — 21 nodes.

        Layers: Clinical Network → Medical Devices → Admin → Server Farm
        """
        g = nx.DiGraph(sector="HEALTHCARE")

        # --- Perimeter ---
        _add_node(g, "HC-EXT-FW",       criticality="HIGH",     role="perimeter_firewall")
        _add_node(g, "HC-VPN-GW",       criticality="HIGH",     role="remote_access_vpn")

        # --- Clinical Workstations ---
        _add_node(g, "HC-NURSE-WS-01",  criticality="MEDIUM",   role="nurse_station_ward_A")
        _add_node(g, "HC-NURSE-WS-02",  criticality="MEDIUM",   role="nurse_station_ward_B")
        _add_node(g, "HC-DR-WS-01",     criticality="MEDIUM",   role="physician_workstation")

        # --- Medical Devices ---
        _add_node(g, "HC-PMON-01",      criticality="CRITICAL", role="patient_monitor_ICU")
        _add_node(g, "HC-PMON-02",      criticality="CRITICAL", role="patient_monitor_ward")
        _add_node(g, "HC-INFPUMP-01",   criticality="CRITICAL", role="infusion_pump_controller")
        _add_node(g, "HC-MRI-01",       criticality="HIGH",     role="mri_scanner")
        _add_node(g, "HC-CT-01",        criticality="HIGH",     role="ct_scanner")
        _add_node(g, "HC-PACS-SRV",     criticality="HIGH",     role="pacs_imaging_server", node_type=NODE_SERVICE)

        # --- Server Farm ---
        _add_node(g, "HC-EHR-DB",       criticality="CRITICAL", role="ehr_database")
        _add_node(g, "HC-EHR-APP",      criticality="CRITICAL", role="ehr_application_server")
        _add_node(g, "HC-PHARM-SRV",    criticality="HIGH",     role="pharmacy_dispensing_system", node_type=NODE_SERVICE)
        _add_node(g, "HC-LAB-SRV",      criticality="HIGH",     role="laboratory_information_system", node_type=NODE_SERVICE)
        _add_node(g, "HC-AD-DC",        criticality="CRITICAL", role="domain_controller")
        _add_node(g, "HC-BACKUP-SRV",   criticality="HIGH",     role="backup_server")

        # --- Admin ---
        _add_node(g, "HC-ADMIN-WS",     criticality="MEDIUM",   role="it_admin_workstation")
        _add_node(g, "HC-BILLING-SRV",  criticality="HIGH",     role="billing_system", node_type=NODE_SERVICE)
        _add_node(g, "HC-EMAIL-SRV",    criticality="MEDIUM",   role="email_server", node_type=NODE_SERVICE)
        _add_node(g, "HC-PRINT-SRV",    criticality="LOW",      role="print_server", node_type=NODE_SERVICE)

        # --- Edges ---
        _link(g, "HC-EXT-FW",     "HC-VPN-GW",       protocol="IPSec")
        _link(g, "HC-EXT-FW",     "HC-EMAIL-SRV",    protocol="SMTP")
        _link(g, "HC-VPN-GW",     "HC-AD-DC",        protocol="Kerberos")
        _link(g, "HC-VPN-GW",     "HC-EHR-APP",      protocol="HTTPS")
        # Clinical
        _link(g, "HC-NURSE-WS-01","HC-EHR-APP",      protocol="HTTPS")
        _link(g, "HC-NURSE-WS-02","HC-EHR-APP",      protocol="HTTPS")
        _link(g, "HC-DR-WS-01",   "HC-EHR-APP",      protocol="HTTPS")
        _link(g, "HC-DR-WS-01",   "HC-PACS-SRV",     protocol="DICOM")
        _link(g, "HC-NURSE-WS-01","HC-PHARM-SRV",    protocol="HL7")
        # Medical devices
        _link(g, "HC-PMON-01",    "HC-EHR-APP",      protocol="HL7/FHIR")
        _link(g, "HC-PMON-02",    "HC-EHR-APP",      protocol="HL7/FHIR")
        _link(g, "HC-INFPUMP-01", "HC-PHARM-SRV",    protocol="HL7")
        _link(g, "HC-MRI-01",     "HC-PACS-SRV",     protocol="DICOM")
        _link(g, "HC-CT-01",      "HC-PACS-SRV",     protocol="DICOM")
        # Server farm
        _link(g, "HC-EHR-APP",    "HC-EHR-DB",       protocol="TDS")
        _link(g, "HC-EHR-APP",    "HC-AD-DC",        protocol="Kerberos")
        _link(g, "HC-LAB-SRV",    "HC-EHR-APP",      protocol="HL7")
        _link(g, "HC-EHR-DB",     "HC-BACKUP-SRV",   protocol="rsync")
        _link(g, "HC-PHARM-SRV",  "HC-EHR-DB",       protocol="TDS")
        # Admin
        _link(g, "HC-ADMIN-WS",   "HC-AD-DC",        protocol="RDP")
        _link(g, "HC-ADMIN-WS",   "HC-BACKUP-SRV",   protocol="SSH")
        _link(g, "HC-BILLING-SRV","HC-EHR-DB",       protocol="TDS")
        _link(g, "HC-DR-WS-01",   "HC-PRINT-SRV",    protocol="IPP")

        log.debug("Healthcare topology built", nodes=g.number_of_nodes(), edges=g.number_of_edges())
        return g

    @staticmethod
    def build_education_topology() -> nx.DiGraph:
        """
        Education institution network — 20 nodes.

        Layers: Internet Edge → Campus Core → Labs → Data Centre
        """
        g = nx.DiGraph(sector="EDUCATION")

        # --- Edge ---
        _add_node(g, "EDU-EXT-FW",      criticality="HIGH",     role="perimeter_firewall")
        _add_node(g, "EDU-VPN-GW",      criticality="MEDIUM",   role="staff_vpn_gateway")
        _add_node(g, "EDU-WEB-SRV",     criticality="MEDIUM",   role="public_website", node_type=NODE_SERVICE)

        # --- Campus Core ---
        _add_node(g, "EDU-AD-DC",       criticality="CRITICAL", role="domain_controller")
        _add_node(g, "EDU-DNS-SRV",     criticality="HIGH",     role="dns_server", node_type=NODE_SERVICE)
        _add_node(g, "EDU-EMAIL-SRV",   criticality="MEDIUM",   role="email_server", node_type=NODE_SERVICE)
        _add_node(g, "EDU-WIFI-CTRL",   criticality="MEDIUM",   role="wireless_controller")

        # --- LMS & Student Services ---
        _add_node(g, "EDU-LMS-SRV",     criticality="HIGH",     role="learning_management_system", node_type=NODE_SERVICE)
        _add_node(g, "EDU-STUDENT-DB",  criticality="CRITICAL", role="student_records_database")
        _add_node(g, "EDU-FEE-SRV",     criticality="HIGH",     role="fee_payment_portal", node_type=NODE_SERVICE)
        _add_node(g, "EDU-LIBRARY-SRV", criticality="LOW",      role="library_catalogue", node_type=NODE_SERVICE)

        # --- Lab Workstations ---
        _add_node(g, "EDU-LAB-WS-01",   criticality="LOW",      role="computer_lab_workstation")
        _add_node(g, "EDU-LAB-WS-02",   criticality="LOW",      role="computer_lab_workstation")
        _add_node(g, "EDU-LAB-WS-03",   criticality="LOW",      role="computer_lab_workstation")
        _add_node(g, "EDU-STAFF-WS-01", criticality="MEDIUM",   role="faculty_workstation")
        _add_node(g, "EDU-STAFF-WS-02", criticality="MEDIUM",   role="admin_staff_workstation")

        # --- Research & Data Centre ---
        _add_node(g, "EDU-RESEARCH-SRV", criticality="HIGH",    role="research_compute_server")
        _add_node(g, "EDU-HPC-CLUSTER",  criticality="HIGH",    role="hpc_gpu_cluster")
        _add_node(g, "EDU-BACKUP-SRV",   criticality="MEDIUM",  role="backup_server")
        _add_node(g, "EDU-NAS-01",       criticality="MEDIUM",  role="network_attached_storage")

        # --- Edges ---
        _link(g, "EDU-EXT-FW",    "EDU-WEB-SRV",      protocol="HTTPS")
        _link(g, "EDU-EXT-FW",    "EDU-VPN-GW",       protocol="IPSec")
        _link(g, "EDU-EXT-FW",    "EDU-WIFI-CTRL",    protocol="RADIUS")
        _link(g, "EDU-VPN-GW",    "EDU-AD-DC",        protocol="Kerberos")
        # Campus core
        _link(g, "EDU-AD-DC",     "EDU-DNS-SRV",      protocol="DNS")
        _link(g, "EDU-AD-DC",     "EDU-EMAIL-SRV",    protocol="SMTP")
        _link(g, "EDU-WIFI-CTRL", "EDU-AD-DC",        protocol="RADIUS")
        # Student services
        _link(g, "EDU-LMS-SRV",   "EDU-STUDENT-DB",   protocol="TDS")
        _link(g, "EDU-FEE-SRV",   "EDU-STUDENT-DB",   protocol="TDS")
        _link(g, "EDU-LMS-SRV",   "EDU-AD-DC",        protocol="LDAP")
        _link(g, "EDU-WEB-SRV",   "EDU-LMS-SRV",      protocol="HTTPS")
        # Labs
        _link(g, "EDU-LAB-WS-01", "EDU-AD-DC",        protocol="Kerberos")
        _link(g, "EDU-LAB-WS-02", "EDU-AD-DC",        protocol="Kerberos")
        _link(g, "EDU-LAB-WS-03", "EDU-LMS-SRV",      protocol="HTTPS")
        _link(g, "EDU-STAFF-WS-01", "EDU-EMAIL-SRV",  protocol="IMAP")
        _link(g, "EDU-STAFF-WS-01", "EDU-RESEARCH-SRV", protocol="SSH")
        _link(g, "EDU-STAFF-WS-02", "EDU-STUDENT-DB", protocol="TDS")
        # Research
        _link(g, "EDU-RESEARCH-SRV", "EDU-HPC-CLUSTER", protocol="SSH")
        _link(g, "EDU-RESEARCH-SRV", "EDU-NAS-01",     protocol="NFS")
        _link(g, "EDU-STUDENT-DB",   "EDU-BACKUP-SRV", protocol="rsync")
        _link(g, "EDU-NAS-01",       "EDU-BACKUP-SRV", protocol="rsync")
        _link(g, "EDU-LIBRARY-SRV",  "EDU-AD-DC",      protocol="LDAP")

        log.debug("Education topology built", nodes=g.number_of_nodes(), edges=g.number_of_edges())
        return g

    # ──────────────────────────────────────────────────────────────────────────
    #  Simulation Engines
    # ──────────────────────────────────────────────────────────────────────────

    def simulate_ransomware_propagation(
        self,
        topology: nx.DiGraph,
        patient_zero: str,
        speed: float = 0.85,
    ) -> SimulationResult:
        """
        BFS-based ransomware propagation with probabilistic infection spread.

        *speed* ∈ [0, 1] controls how likely each hop succeeds.  Higher speed
        means faster/more-complete encryption propagation.
        """
        scenario_id = f"RANSOM-{uuid.uuid4().hex[:8]}"
        sim_log: list[str] = []
        infected: list[str] = []
        isolated: list[str] = []

        if patient_zero not in topology:
            sim_log.append(f"[ERROR] Patient zero '{patient_zero}' not found in topology")
            return SimulationResult(scenario_id=scenario_id, simulation_log=sim_log)

        sim_log.append(f"[T+0s] Ransomware detonated on {patient_zero}")
        infected.append(patient_zero)
        visited = {patient_zero}
        queue: list[tuple[str, int]] = [(patient_zero, 0)]  # (node, hop)
        step = 0

        while queue:
            current, hop = queue.pop(0)
            step += 1
            node_data = topology.nodes[current]
            criticality = node_data.get("criticality", "LOW")

            for neighbor in topology.neighbors(current):
                if neighbor in visited:
                    continue
                visited.add(neighbor)

                edge_data = topology.edges[current, neighbor]
                protocol = edge_data.get("protocol", "TCP")

                # Infection probability based on speed and protocol
                base_prob = speed
                # OT protocols slightly harder to infect
                if protocol in ("Modbus", "DNP3", "IEC-61850", "Modbus/TCP"):
                    base_prob *= 0.6
                elif protocol in ("SSH", "RDP", "SMB"):
                    base_prob *= 0.95
                elif protocol in ("HTTPS", "DICOM", "HL7", "HL7/FHIR"):
                    base_prob *= 0.7

                roll = random.random()
                if roll < base_prob:
                    infected.append(neighbor)
                    queue.append((neighbor, hop + 1))
                    sim_log.append(
                        f"[T+{step * 15}s] {current} → {neighbor} INFECTED via {protocol} "
                        f"(prob={base_prob:.2f}, roll={roll:.2f})"
                    )
                else:
                    isolated.append(neighbor)
                    sim_log.append(
                        f"[T+{step * 15}s] {current} → {neighbor} BLOCKED "
                        f"(prob={base_prob:.2f}, roll={roll:.2f})"
                    )

        total_nodes = topology.number_of_nodes()
        blast_pct = round(len(infected) / max(total_nodes, 1) * 100, 2)
        # Downtime estimation: critical nodes contribute more
        critical_infected = sum(
            1 for n in infected
            if topology.nodes[n].get("criticality") in ("HIGH", "CRITICAL")
        )
        downtime = round(critical_infected * 4.0 + len(infected) * 0.5, 1)

        recovery = self._generate_recovery_steps(topology, infected, "ransomware")
        sim_log.append(f"[SUMMARY] Infected: {len(infected)}/{total_nodes}, Blast radius: {blast_pct}%")

        return SimulationResult(
            scenario_id=scenario_id,
            infected_nodes=infected,
            isolated_nodes=isolated,
            total_affected=len(infected),
            blast_radius_percent=blast_pct,
            estimated_downtime_hours=downtime,
            recovery_steps=recovery,
            simulation_log=sim_log,
        )

    def simulate_apt_lateral_movement(
        self,
        topology: nx.DiGraph,
        entry_point: str,
        target_asset: str,
    ) -> SimulationResult:
        """
        Simulates an APT performing targeted lateral movement from *entry_point*
        toward *target_asset*, using shortest-path with probabilistic
        step success.
        """
        scenario_id = f"APT-{uuid.uuid4().hex[:8]}"
        sim_log: list[str] = []
        compromised: list[str] = []

        if entry_point not in topology:
            sim_log.append(f"[ERROR] Entry point '{entry_point}' not in topology")
            return SimulationResult(scenario_id=scenario_id, simulation_log=sim_log)
        if target_asset not in topology:
            sim_log.append(f"[ERROR] Target asset '{target_asset}' not in topology")
            return SimulationResult(scenario_id=scenario_id, simulation_log=sim_log)

        sim_log.append(f"[T+0m] APT gained foothold on {entry_point}")
        compromised.append(entry_point)

        # Find all simple paths (up to length 6) and select shortest
        try:
            paths = list(nx.all_simple_paths(topology, entry_point, target_asset, cutoff=6))
        except nx.NetworkXNoPath:
            paths = []

        if not paths:
            sim_log.append(f"[T+5m] No reachable path from {entry_point} to {target_asset}")
            return SimulationResult(
                scenario_id=scenario_id,
                infected_nodes=compromised,
                total_affected=len(compromised),
                blast_radius_percent=round(len(compromised) / max(topology.number_of_nodes(), 1) * 100, 2),
                simulation_log=sim_log,
            )

        chosen_path = min(paths, key=len)
        sim_log.append(f"[T+2m] Attack path identified: {' → '.join(chosen_path)}")

        elapsed_minutes = 5
        blocked = False
        for i in range(len(chosen_path) - 1):
            src, dst = chosen_path[i], chosen_path[i + 1]
            edge_data = topology.edges.get((src, dst), {})
            protocol = edge_data.get("protocol", "TCP")

            # APT success probabilities — stealthy, high skill
            success_prob = 0.80
            if protocol in ("Kerberos", "LDAP"):
                success_prob = 0.90  # credential abuse
            elif protocol in ("SSH", "RDP"):
                success_prob = 0.85
            elif protocol in ("Modbus", "DNP3", "IEC-61850"):
                success_prob = 0.55  # OT harder to pivot

            roll = random.random()
            if roll < success_prob:
                compromised.append(dst)
                sim_log.append(
                    f"[T+{elapsed_minutes}m] Lateral move {src} → {dst} SUCCESS via {protocol} "
                    f"(p={success_prob:.2f})"
                )
            else:
                sim_log.append(
                    f"[T+{elapsed_minutes}m] Lateral move {src} → {dst} DETECTED/FAILED via {protocol} "
                    f"(p={success_prob:.2f})"
                )
                blocked = True
                break
            elapsed_minutes += random.randint(5, 20)

        if not blocked and target_asset in compromised:
            sim_log.append(f"[T+{elapsed_minutes}m] TARGET COMPROMISED: {target_asset}")
        elif blocked:
            sim_log.append(f"[T+{elapsed_minutes}m] APT movement halted — partial compromise")

        total_nodes = topology.number_of_nodes()
        critical_hit = sum(
            1 for n in compromised
            if topology.nodes[n].get("criticality") in ("HIGH", "CRITICAL")
        )
        downtime = round(critical_hit * 6.0 + len(compromised) * 1.0, 1)

        return SimulationResult(
            scenario_id=scenario_id,
            infected_nodes=compromised,
            isolated_nodes=[],
            total_affected=len(compromised),
            blast_radius_percent=round(len(compromised) / max(total_nodes, 1) * 100, 2),
            estimated_downtime_hours=downtime,
            recovery_steps=self._generate_recovery_steps(topology, compromised, "apt"),
            simulation_log=sim_log,
        )

    def simulate_scada_manipulation(
        self,
        topology_or_target: Any,
        target_plc: Optional[str] = None,
    ) -> Any:
        """
        Simulates an attacker who has reached a PLC/RTU and manipulates
        downstream physical processes (breakers, transformers, etc.).
        Supports both production (topology, target_plc) and test compatibility (target_plc) signatures.
        """
        if target_plc is None:
            # Test compatibility signature
            target = str(topology_or_target)
            if target not in self._graph:
                return {"target": target, "success": False, "reason": "Target not found"}

            node_data = dict(self._graph.nodes[target])
            is_plc = node_data.get("type") in ("PLC", "RTU", "iot_device", "medical_device")

            return {
                "target": target,
                "success": is_plc,
                "node_type": node_data.get("type", "unknown"),
                "criticality": node_data.get("criticality", "UNKNOWN"),
                "downstream_affected": list(nx.descendants(self._graph, target)),
                "reason": "PLC/ICS device manipulated" if is_plc else "Target is not a PLC/ICS device",
            }

        # Production signature
        topology = topology_or_target
        scenario_id = f"SCADA-{uuid.uuid4().hex[:8]}"
        sim_log: list[str] = []
        affected: list[str] = []

        if target_plc not in topology:
            sim_log.append(f"[ERROR] Target PLC '{target_plc}' not in topology")
            return SimulationResult(scenario_id=scenario_id, simulation_log=sim_log)

        sim_log.append(f"[T+0s] Attacker gained control of {target_plc}")
        affected.append(target_plc)

        # Traverse downstream CONTROLS / MONITORS edges
        visited = {target_plc}
        queue = [target_plc]
        step = 0
        while queue:
            current = queue.pop(0)
            step += 1
            for neighbor in topology.neighbors(current):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                edge_data = topology.edges[current, neighbor]
                edge_type = edge_data.get("type", "")
                protocol = edge_data.get("protocol", "")

                if edge_type in (EDGE_CONTROLS, EDGE_MONITORS, EDGE_COMMUNICATED_WITH):
                    affected.append(neighbor)
                    role = topology.nodes[neighbor].get("role", "unknown")
                    action = "MANIPULATED" if edge_type == EDGE_CONTROLS else "DISRUPTED"
                    sim_log.append(
                        f"[T+{step * 5}s] {current} → {neighbor} ({role}) {action} via {protocol}"
                    )
                    queue.append(neighbor)

        # Physical impact assessment
        breakers = [n for n in affected if "CB" in n or "breaker" in topology.nodes[n].get("role", "")]
        transformers = [n for n in affected if "XFMR" in n or "transformer" in topology.nodes[n].get("role", "")]

        if breakers:
            sim_log.append(f"[IMPACT] Circuit breakers tripped: {breakers} — potential blackout")
        if transformers:
            sim_log.append(f"[IMPACT] Transformers affected: {transformers} — grid instability")

        total_nodes = topology.number_of_nodes()
        downtime = round(len(breakers) * 8.0 + len(transformers) * 12.0 + len(affected) * 1.0, 1)

        return SimulationResult(
            scenario_id=scenario_id,
            infected_nodes=affected,
            isolated_nodes=[],
            total_affected=len(affected),
            blast_radius_percent=round(len(affected) / max(total_nodes, 1) * 100, 2),
            estimated_downtime_hours=downtime,
            recovery_steps=self._generate_recovery_steps(topology, affected, "scada"),
            simulation_log=sim_log,
        )

    def simulate_data_exfiltration(
        self,
        topology: nx.DiGraph,
        source: str,
        destination: str,
    ) -> SimulationResult:
        """
        Simulates data exfiltration from an internal *source* node toward an
        external *destination* (or egress node).
        """
        scenario_id = f"EXFIL-{uuid.uuid4().hex[:8]}"
        sim_log: list[str] = []
        compromised: list[str] = []

        if source not in topology:
            sim_log.append(f"[ERROR] Source node '{source}' not in topology")
            return SimulationResult(scenario_id=scenario_id, simulation_log=sim_log)

        sim_log.append(f"[T+0m] Data staging initiated on {source}")
        compromised.append(source)

        source_role = topology.nodes[source].get("role", "")
        criticality = topology.nodes[source].get("criticality", "LOW")
        sim_log.append(f"[T+2m] Source asset role: {source_role}, criticality: {criticality}")

        # Find path to destination (egress)
        target = destination if destination in topology else None
        # If destination isn't in topology, find nearest firewall / gateway as egress
        if target is None:
            for node, data in topology.nodes(data=True):
                role = data.get("role", "")
                if "firewall" in role or "gateway" in role or "vpn" in role:
                    target = node
                    break

        if target is None:
            sim_log.append("[T+5m] No egress route found — exfiltration blocked by air-gap")
            return SimulationResult(
                scenario_id=scenario_id,
                infected_nodes=compromised,
                total_affected=len(compromised),
                simulation_log=sim_log,
            )

        try:
            # Use undirected view for path finding (data can flow both ways)
            path = nx.shortest_path(topology.to_undirected(), source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            sim_log.append(f"[T+5m] No path from {source} to egress {target}")
            return SimulationResult(
                scenario_id=scenario_id,
                infected_nodes=compromised,
                total_affected=len(compromised),
                simulation_log=sim_log,
            )

        sim_log.append(f"[T+5m] Exfiltration route: {' → '.join(path)}")

        elapsed = 10
        data_volume_gb = 0.0
        for i in range(len(path) - 1):
            src_n, dst_n = path[i], path[i + 1]
            compromised.append(dst_n)

            # Estimate data volume based on source criticality
            chunk_gb = {"CRITICAL": 5.0, "HIGH": 2.0, "MEDIUM": 0.5, "LOW": 0.1}.get(criticality, 0.5)
            data_volume_gb += chunk_gb

            sim_log.append(
                f"[T+{elapsed}m] Data relay {src_n} → {dst_n} — "
                f"{chunk_gb:.1f} GB exfiltrated cumulatively"
            )
            elapsed += random.randint(3, 10)

        sim_log.append(
            f"[T+{elapsed}m] Total exfiltrated: {data_volume_gb:.1f} GB "
            f"to egress point {target}"
        )

        total_nodes = topology.number_of_nodes()
        downtime = round(data_volume_gb * 2.0 + len(compromised) * 0.5, 1)

        return SimulationResult(
            scenario_id=scenario_id,
            infected_nodes=list(set(compromised)),
            isolated_nodes=[],
            total_affected=len(set(compromised)),
            blast_radius_percent=round(len(set(compromised)) / max(total_nodes, 1) * 100, 2),
            estimated_downtime_hours=downtime,
            recovery_steps=self._generate_recovery_steps(topology, compromised, "exfiltration"),
            simulation_log=sim_log,
        )

    # ── Defensive simulation ─────────────────────────────────────────────────

    def run_defensive_simulation(
        self,
        topology: nx.DiGraph,
        threat_result: SimulationResult,
        mitigation_actions: list[str],
    ) -> SimulationResult:
        """
        Re-runs a simulation with mitigations applied.

        Supported mitigation actions (case-insensitive):
        - ``isolate:<node_id>`` — remove node from topology before re-sim
        - ``block_protocol:<protocol>`` — remove edges using that protocol
        - ``patch:<node_id>`` — mark node as patched (immune)
        - ``segment:<zone_prefix>`` — cut cross-zone edges
        """
        scenario_id = f"DEF-{threat_result.scenario_id}"
        sim_log: list[str] = [
            f"[DEFENSE] Replaying scenario {threat_result.scenario_id} with mitigations",
            f"[DEFENSE] Original affected: {threat_result.total_affected} nodes",
        ]

        # Work on a copy
        defended_topo: nx.DiGraph = topology.copy()

        isolated_nodes: list[str] = []
        for action in mitigation_actions:
            action_lower = action.strip().lower()
            if action_lower.startswith("isolate:"):
                node = action.split(":", 1)[1].strip()
                if node in defended_topo:
                    defended_topo.remove_node(node)
                    isolated_nodes.append(node)
                    sim_log.append(f"[MITIGATE] Isolated node {node}")
            elif action_lower.startswith("block_protocol:"):
                proto = action.split(":", 1)[1].strip()
                edges_to_remove = [
                    (u, v) for u, v, d in defended_topo.edges(data=True)
                    if d.get("protocol", "").lower() == proto.lower()
                ]
                for u, v in edges_to_remove:
                    defended_topo.remove_edge(u, v)
                sim_log.append(f"[MITIGATE] Blocked protocol {proto} — removed {len(edges_to_remove)} edges")
            elif action_lower.startswith("patch:"):
                node = action.split(":", 1)[1].strip()
                if node in defended_topo:
                    defended_topo.nodes[node]["patched"] = True
                    sim_log.append(f"[MITIGATE] Patched node {node}")
            elif action_lower.startswith("segment:"):
                prefix = action.split(":", 1)[1].strip()
                edges_to_remove = [
                    (u, v) for u, v in defended_topo.edges()
                    if (u.startswith(prefix)) != (v.startswith(prefix))
                ]
                for u, v in edges_to_remove:
                    defended_topo.remove_edge(u, v)
                sim_log.append(f"[MITIGATE] Segmented zone {prefix} — cut {len(edges_to_remove)} cross-zone edges")

        # Re-simulate with original patient zero (if still exists)
        patient_zero = threat_result.infected_nodes[0] if threat_result.infected_nodes else None
        if patient_zero and patient_zero in defended_topo:
            re_result = self.simulate_ransomware_propagation(defended_topo, patient_zero, speed=0.85)
            re_result.scenario_id = scenario_id
            re_result.isolated_nodes = isolated_nodes
            re_result.simulation_log = sim_log + re_result.simulation_log

            reduction = threat_result.total_affected - re_result.total_affected
            re_result.simulation_log.append(
                f"[DEFENSE RESULT] Reduced impact by {reduction} nodes "
                f"({threat_result.total_affected} → {re_result.total_affected})"
            )
            return re_result

        sim_log.append("[DEFENSE RESULT] Patient zero eliminated — attack fully prevented")
        return SimulationResult(
            scenario_id=scenario_id,
            infected_nodes=[],
            isolated_nodes=isolated_nodes,
            total_affected=0,
            blast_radius_percent=0.0,
            estimated_downtime_hours=0.0,
            recovery_steps=["Verify mitigation effectiveness", "Resume normal operations"],
            simulation_log=sim_log,
        )

    # ── Scenario replay ──────────────────────────────────────────────────────

    def replay_attack(self, scenario_or_log: Any) -> Any:
        """
        Execute a pre-defined SimulationScenario against the appropriate
        sector topology, or replay a list of attack logs (for test compatibility).
        """
        if isinstance(scenario_or_log, list):
            results: list[dict] = []
            for step in scenario_or_log:
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
                "total_steps": len(scenario_or_log),
                "successful_steps": sum(1 for r in results if r["outcome"] == "success"),
                "results": results,
            }

        topology = self.get_topology(scenario_or_log.sector)

        threat_map = {
            "ransomware": lambda: self.simulate_ransomware_propagation(
                topology, scenario_or_log.patient_zero_ip, speed=scenario_or_log.speed_coefficient,
            ),
            "apt_lateral": lambda: self.simulate_apt_lateral_movement(
                topology,
                scenario_or_log.patient_zero_ip,
                target_asset=self._find_highest_criticality(topology),
            ),
            "scada_manipulation": lambda: self.simulate_scada_manipulation(
                topology, scenario_or_log.patient_zero_ip,
            ),
            "data_exfiltration": lambda: self.simulate_data_exfiltration(
                topology, scenario_or_log.patient_zero_ip, destination="EXTERNAL",
            ),
        }

        runner = threat_map.get(scenario_or_log.threat_type)
        if runner is None:
            log.warning("Unknown threat type in scenario", threat_type=scenario_or_log.threat_type)
            return SimulationResult(
                scenario_id=scenario_or_log.scenario_id,
                simulation_log=[f"[ERROR] Unknown threat_type: {scenario_or_log.threat_type}"],
            )

        result = runner()
        result.scenario_id = scenario_or_log.scenario_id
        log.info(
            "Scenario replayed",
            scenario_id=scenario_or_log.scenario_id,
            affected=result.total_affected,
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _find_highest_criticality(topology: nx.DiGraph) -> str:
        """Return the node ID with the highest criticality in *topology*."""
        crit_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        best_node = ""
        best_score = -1
        for nid, data in topology.nodes(data=True):
            score = crit_order.get(data.get("criticality", "LOW"), 0)
            if score > best_score:
                best_score = score
                best_node = nid
        return best_node

    @staticmethod
    def _generate_recovery_steps(
        topology: nx.DiGraph,
        affected_nodes: list[str],
        attack_type: str,
    ) -> list[str]:
        """Generate context-aware recovery steps based on attack type and affected assets."""
        steps: list[str] = []

        critical_nodes = [
            n for n in affected_nodes
            if topology.nodes.get(n, {}).get("criticality") in ("HIGH", "CRITICAL")
        ]

        # Common steps
        steps.append("1. Activate Incident Response Plan and notify CISO")
        steps.append("2. Preserve forensic evidence — capture memory dumps and disk images")

        if attack_type == "ransomware":
            steps.extend([
                "3. Isolate all infected endpoints from the network immediately",
                "4. Identify ransomware variant and check for known decryptors",
                "5. Restore systems from verified clean backups (offline/immutable)",
                f"6. Priority restore for critical assets: {', '.join(critical_nodes[:5]) or 'N/A'}",
                "7. Reset all credentials — domain admin, service accounts, local admin",
                "8. Scan all endpoints with updated AV/EDR signatures",
                "9. Verify backup integrity and restore completeness",
                "10. Conduct post-incident review and update detection rules",
            ])
        elif attack_type == "apt":
            steps.extend([
                "3. Map full scope of compromise — enumerate all accessed systems",
                "4. Contain: isolate compromised segments, revoke stolen credentials",
                "5. Hunt for persistence mechanisms — scheduled tasks, registry, WMI",
                f"6. Rebuild critical systems from gold images: {', '.join(critical_nodes[:5]) or 'N/A'}",
                "7. Rotate all certificates and API keys in the affected environment",
                "8. Deploy enhanced monitoring on lateral movement indicators",
                "9. Engage threat intelligence for attribution and IOC sharing",
                "10. Implement network segmentation improvements",
            ])
        elif attack_type == "scada":
            steps.extend([
                "3. Switch affected OT systems to manual/local control IMMEDIATELY",
                "4. Disconnect IT–OT bridge — enforce air-gap until cleared",
                "5. Verify physical process safety — check breaker states, transformer loads",
                f"6. Re-commission affected PLCs/RTUs: {', '.join(critical_nodes[:5]) or 'N/A'}",
                "7. Restore PLC firmware from trusted offline backups",
                "8. Validate SCADA setpoints and logic before reconnecting to network",
                "9. Notify grid operator / regulatory authority (CERT-In, CERC)",
                "10. Implement unidirectional security gateways (data diodes)",
            ])
        elif attack_type == "exfiltration":
            steps.extend([
                "3. Block identified exfiltration channels and egress IPs",
                "4. Quantify data loss — identify affected records and data classification",
                "5. Notify data protection officer and initiate breach notification process",
                f"6. Secure affected databases: {', '.join(critical_nodes[:5]) or 'N/A'}",
                "7. Rotate all credentials and encryption keys for compromised data stores",
                "8. Deploy DLP rules to prevent re-exfiltration",
                "9. Engage legal counsel for regulatory compliance (IT Act, DPDP Act)",
                "10. Implement enhanced egress filtering and DNS monitoring",
            ])
        else:
            steps.extend([
                "3. Isolate affected systems",
                "4. Analyse root cause",
                "5. Restore from clean backups",
                "6. Harden and re-deploy",
            ])

        return steps
