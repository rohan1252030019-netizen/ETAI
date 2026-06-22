from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel

from soc.soar_orchestrator import SOAROrchestrator, Playbook, PlaybookExecutionResult
from utils.logger import log

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR Response"])

def get_soar_orchestrator(request: Request) -> SOAROrchestrator:
    """Retrieve or initialize the SOAROrchestrator instance from app state."""
    state = getattr(request.app.state, "immunex", {})
    if "soar_orchestrator" not in state:
        log.info("Lazy initializing SOAROrchestrator in SOAR routes", subsystem="api_soar")
        state["soar_orchestrator"] = SOAROrchestrator()
    return state["soar_orchestrator"]


class ExecutePlaybookRequest(BaseModel):
    playbook_name: str
    context: dict[str, Any]


@router.get("/playbooks", response_model=list[Playbook])
async def get_playbooks(request: Request):
    """Retrieve all loaded containment and response playbooks."""
    try:
        orchestrator = get_soar_orchestrator(request)
        return orchestrator.playbooks
    except Exception as e:
        log.error("Failed to list playbooks", error=str(e), subsystem="api_soar")
        raise HTTPException(status_code=500, detail=f"Failed to list playbooks: {str(e)}")


@router.get("/executions")
async def get_executions(request: Request):
    """Retrieve all playbook execution records/audit trail."""
    try:
        orchestrator = get_soar_orchestrator(request)
        return list(orchestrator.executions.values())
    except Exception as e:
        log.error("Failed to list playbook executions", error=str(e), subsystem="api_soar")
        raise HTTPException(status_code=500, detail=f"Failed to list executions: {str(e)}")


@router.post("/execute", response_model=PlaybookExecutionResult)
async def execute_playbook(request: Request, payload: ExecutePlaybookRequest):
    """Manually trigger execution of a response playbook with a custom context."""
    try:
        orchestrator = get_soar_orchestrator(request)
        # Find playbook by name
        matched_pb = None
        for pb in orchestrator.playbooks:
            if pb.name.lower() == payload.playbook_name.lower():
                matched_pb = pb
                break
                
        if not matched_pb:
            raise HTTPException(status_code=404, detail=f"Playbook '{payload.playbook_name}' not found.")
            
        result = orchestrator.execute_playbook(matched_pb, payload.context)
        return result
    except HTTPException:
        raise
    except Exception as e:
        log.error("Failed manual playbook execution", error=str(e), playbook=payload.playbook_name, subsystem="api_soar")
        raise HTTPException(status_code=500, detail=f"Error executing playbook: {str(e)}")
