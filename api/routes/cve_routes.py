from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field

from core.cve_prioritization import CVEPrioritizationEngine, CVERiskAssessment, AssetRecord
from utils.logger import log

router = APIRouter(prefix="/api/v1/cve", tags=["CVE Prioritization"])

def get_cve_engine(request: Request) -> CVEPrioritizationEngine:
    """Retrieve or initialize the CVEPrioritizationEngine instance from app state."""
    state = getattr(request.app.state, "immunex", {})
    if "cve_engine" not in state:
        log.info("Lazy initializing CVEPrioritizationEngine in CVE routes", subsystem="api_cve")
        state["cve_engine"] = CVEPrioritizationEngine()
    return state["cve_engine"]


class AssessAssetRequest(BaseModel):
    asset_ip: str


@router.get("/top-threats", response_model=list[CVERiskAssessment])
async def get_top_threats(
    request: Request,
    limit: int = Query(10, ge=1, le=100, description="Max threats to return")
):
    """Retrieve top prioritized vulnerabilities across all assets."""
    try:
        engine = get_cve_engine(request)
        threats = engine.get_top_threats(limit=limit)
        return threats
    except Exception as e:
        log.error("Failed to retrieve top CVE threats", error=str(e), subsystem="api_cve")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve top threats: {str(e)}")


@router.post("/assess", response_model=list[CVERiskAssessment])
async def assess_asset(request: Request, payload: AssessAssetRequest):
    """Trigger vulnerability risk assessment for a specific asset IP."""
    try:
        engine = get_cve_engine(request)
        assessments = engine.assess_asset(payload.asset_ip)
        return assessments
    except Exception as e:
        log.error("Failed to assess asset CVE risks", error=str(e), asset_ip=payload.asset_ip, subsystem="api_cve")
        raise HTTPException(status_code=500, detail=f"Failed to assess asset: {str(e)}")


@router.get("/inventory")
async def get_inventory(request: Request):
    """Retrieve all tracked assets and their vulnerability counts."""
    try:
        engine = get_cve_engine(request)
        # Query db stats and inventory from cve_db
        db = engine._db
        assets = db.list_assets()
        inventory = []
        for asset in assets:
            ip = asset["asset_ip"]
            # count vulnerabilities for this asset
            vulns = db.get_asset_vulnerabilities(ip)
            inventory.append({
                "asset_ip": ip,
                "asset_name": asset["asset_name"],
                "criticality": asset["criticality"],
                "asset_zone": asset["asset_zone"],
                "vulnerability_count": len(vulns),
                "metadata": asset.get("metadata", {})
            })
        return inventory
    except Exception as e:
        log.error("Failed to retrieve CVE asset inventory", error=str(e), subsystem="api_cve")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve inventory: {str(e)}")
