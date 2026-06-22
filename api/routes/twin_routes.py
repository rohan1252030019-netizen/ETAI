from __future__ import annotations

from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.digital_twin_simulator import IndustrialTwinSimulator, CNISector, SimulationScenario, SimulationResult
from utils.logger import log

router = APIRouter(prefix="/api/v1/twin", tags=["Digital Twin"])

def get_twin_simulator(request: Request) -> IndustrialTwinSimulator:
    """Retrieve or initialize the IndustrialTwinSimulator instance from app state."""
    state = getattr(request.app.state, "immunex", {})
    if "twin_simulator" not in state:
        log.info("Lazy initializing IndustrialTwinSimulator in twin routes", subsystem="api_twin")
        state["twin_simulator"] = IndustrialTwinSimulator()
    return state["twin_simulator"]


class SimulateRequest(BaseModel):
    sector: CNISector
    threat_type: str = Field(description="One of: ransomware, apt_lateral, scada_manipulation, data_exfiltration")
    patient_zero_ip: Optional[str] = None
    speed_coefficient: float = 0.85
    mitigations: list[str] = Field(default_factory=list)


@router.post("/simulate", response_model=SimulationResult)
async def simulate_scenario(request: Request, payload: SimulateRequest):
    """Run a threat simulation against a sector's network twin."""
    try:
        sim = get_twin_simulator(request)
        
        # Determine patient zero based on sector if not provided
        patient_zero = payload.patient_zero_ip
        if not patient_zero:
            if payload.sector == CNISector.ENERGY_GRID:
                patient_zero = "10.10.1.30"  # Historian-01 or HMI
            elif payload.sector == CNISector.HEALTHCARE:
                patient_zero = "192.168.1.50"
            elif payload.sector == CNISector.GOVERNMENT:
                patient_zero = "10.0.1.20"
            else:
                patient_zero = "192.168.10.10"
                
        scenario = SimulationScenario(
            name=f"Manual Simulation: {payload.threat_type} on {payload.sector}",
            sector=payload.sector,
            patient_zero_ip=patient_zero,
            threat_type=payload.threat_type,
            speed_coefficient=payload.speed_coefficient
        )
        
        # First run base attack
        base_result = sim.replay_attack(scenario)
        
        # If mitigations are provided, run defensive replay
        if payload.mitigations:
            topology = sim.get_topology(payload.sector)
            defended_result = sim.run_defensive_simulation(topology, base_result, payload.mitigations)
            return defended_result
            
        return base_result
    except Exception as e:
        log.error("Failed to run twin simulation", error=str(e), sector=payload.sector, threat_type=payload.threat_type, subsystem="api_twin")
        raise HTTPException(status_code=500, detail=f"Failed to run simulation: {str(e)}")


@router.get("/topology-data")
async def get_sector_topology(request: Request, sector: CNISector):
    """Retrieve raw node and link details for rendering a sector-specific digital twin graph."""
    try:
        sim = get_twin_simulator(request)
        topo = sim.get_topology(sector)
        
        nodes = []
        for n, d in topo.nodes(data=True):
            nodes.append({
                "id": n,
                "type": d.get("type", "generic"),
                "criticality": d.get("criticality", "MEDIUM"),
                "patched": d.get("patched", False)
            })
            
        edges = []
        for u, v, d in topo.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "type": d.get("type", "communicated_with")
            })
            
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        log.error("Failed to retrieve sector topology details", error=str(e), sector=sector, subsystem="api_twin")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve topology data: {str(e)}")
