from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from core.business_impact import ExecutiveImpactEngine, ExecutiveReport
from utils.logger import log

router = APIRouter(prefix="/api/v1/impact", tags=["Executive Impact"])

def get_impact_engine(request: Request) -> ExecutiveImpactEngine:
    """Retrieve or initialize the ExecutiveImpactEngine instance from app state."""
    state = getattr(request.app.state, "immunex", {})
    if "impact_engine" not in state:
        log.info("Lazy initializing ExecutiveImpactEngine in impact routes", subsystem="api_impact")
        state["impact_engine"] = ExecutiveImpactEngine()
    return state["impact_engine"]


@router.get("/dashboard")
async def get_dashboard_metrics(request: Request):
    """Retrieve high-level financial, citizen, and downtime avoidance metrics for dashboard KPI cards."""
    try:
        engine = get_impact_engine(request)
        return engine.get_dashboard_metrics()
    except Exception as e:
        log.error("Failed to fetch dashboard metrics", error=str(e), subsystem="api_impact")
        raise HTTPException(status_code=500, detail=f"Failed to fetch dashboard metrics: {str(e)}")


@router.get("/report")
async def get_executive_report(request: Request):
    """Generates an executive impact report based on current incident stats."""
    try:
        engine = get_impact_engine(request)
        # Fetch incidents from request app state or seed defaults
        state = getattr(request.app.state, "immunex", {})
        recent_mitigations = state.get("recent_mitigations", [])
        
        # Format as minimal incidents for generator
        incidents = []
        for mit in recent_mitigations:
            incidents.append({
                "status": "SUCCESS" if mit.get("verdict") == "APPROVED" else "FAILED"
            })
            
        # fallback to seed incidents if empty
        if not incidents:
            incidents = [{"status": "SUCCESS"}, {"status": "SUCCESS"}, {"status": "SUCCESS"}]
            
        report = engine.generate_executive_report(incidents=incidents, assets=[], sector="ENERGY_GRID")
        return report
    except Exception as e:
        log.error("Failed to generate executive report", error=str(e), subsystem="api_impact")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
