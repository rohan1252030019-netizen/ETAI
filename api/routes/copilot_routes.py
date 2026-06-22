from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel

from core.copilot_engine import CopilotEngine, CopilotQuery, CopilotResponse
from utils.logger import log

router = APIRouter(prefix="/api/v1/copilot", tags=["Upgraded SOC Copilot"])

def get_copilot_engine(request: Request) -> CopilotEngine:
    """Retrieve or initialize the CopilotEngine instance from app state."""
    state = getattr(request.app.state, "immunex", {})
    if "copilot_engine" not in state:
        log.info("Lazy initializing CopilotEngine in copilot routes", subsystem="api_copilot")
        state["copilot_engine"] = CopilotEngine()
    return state["copilot_engine"]


@router.post("/query", response_model=CopilotResponse)
async def query_copilot(request: Request, payload: CopilotQuery):
    """Upgraded SOC Copilot query processing with auto-intent routing."""
    try:
        engine = get_copilot_engine(request)
        response = engine.process_natural_language(payload.query_text)
        return response
    except Exception as e:
        log.error("Failed to process copilot query", error=str(e), query=payload.query_text, subsystem="api_copilot")
        raise HTTPException(status_code=500, detail=f"Failed to process copilot query: {str(e)}")
