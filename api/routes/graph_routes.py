from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field

from core.attack_graph_engine import AttackGraphEngine, AttackPath, BlastRadiusResult, TopologySummary
from utils.logger import log

router = APIRouter(prefix="/api/v1/graph", tags=["Attack Graph"])

def get_graph_engine(request: Request) -> AttackGraphEngine:
    """Retrieve or initialize the AttackGraphEngine instance from app state."""
    state = getattr(request.app.state, "immunex", {})
    if "graph_engine" not in state:
        log.info("Lazy initializing AttackGraphEngine in graph routes", subsystem="api_graph")
        state["graph_engine"] = AttackGraphEngine(use_neo4j=True, bootstrap=True)
    return state["graph_engine"]


class SyncTopologyRequest(BaseModel):
    assets: list[dict[str, Any]] = Field(default_factory=list)
    connections: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/topology", response_model=TopologySummary)
async def get_topology(request: Request):
    """Retrieve full topology summary of the current network."""
    try:
        engine = get_graph_engine(request)
        summary = engine.get_topology_summary()
        return summary
    except Exception as e:
        log.error("Failed to retrieve topology summary", error=str(e), subsystem="api_graph")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve topology: {str(e)}")


@router.get("/path", response_model=AttackPath)
async def get_attack_path(
    request: Request,
    source: str = Query(..., description="Source IP address"),
    target: str = Query(..., description="Target IP address")
):
    """Retrieve shortest attack path between source and target IPs."""
    try:
        engine = get_graph_engine(request)
        path = engine.find_shortest_attack_path(source, target)
        if not path:
            raise HTTPException(status_code=404, detail=f"No attack path found from {source} to {target}")
        return path
    except HTTPException:
        raise
    except Exception as e:
        log.error("Failed to compute shortest path", error=str(e), source=source, target=target, subsystem="api_graph")
        raise HTTPException(status_code=500, detail=f"Error computing attack path: {str(e)}")


@router.get("/blast-radius", response_model=BlastRadiusResult)
async def get_blast_radius(
    request: Request,
    ip: str = Query(..., description="Compromised node IP address")
):
    """Retrieve blast radius analysis for a compromised node."""
    try:
        engine = get_graph_engine(request)
        result = engine.calculate_blast_radius(ip)
        return result
    except Exception as e:
        log.error("Failed to calculate blast radius", error=str(e), ip=ip, subsystem="api_graph")
        raise HTTPException(status_code=500, detail=f"Error calculating blast radius: {str(e)}")


@router.post("/sync")
async def sync_topology(request: Request, payload: SyncTopologyRequest):
    """Triggers topology rebuild from provided asset inventory and connections."""
    try:
        engine = get_graph_engine(request)
        if not payload.assets and not payload.connections:
            # Rebuild using default topology
            engine._bootstrap_default_topology()
            summary = engine.get_topology_summary()
            return {"status": "SUCCESS", "message": "Topology reset to default CNI schema.", "summary": summary}
        
        result = engine.build_topology(payload.assets, payload.connections)
        return {"status": "SUCCESS", "message": "Topology synced successfully.", "result": result}
    except Exception as e:
        log.error("Failed to sync topology", error=str(e), subsystem="api_graph")
        raise HTTPException(status_code=500, detail=f"Error syncing topology: {str(e)}")
