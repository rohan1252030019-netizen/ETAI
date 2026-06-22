# IMMUNEX API Routes Package
# Modular route registration for National Cyber Resilience Platform

from fastapi import APIRouter

# Import the legacy router
from api.routes.legacy_routes import router as legacy_router

# Import new sub-routers
from api.routes.graph_routes import router as graph_router
from api.routes.cve_routes import router as cve_router
from api.routes.soar_routes import router as soar_router
from api.routes.impact_routes import router as impact_router
from api.routes.twin_routes import router as twin_router
from api.routes.agent_routes import router as agent_router
from api.routes.copilot_routes import router as copilot_router

# Create a master router
router = APIRouter()

# Include all routes under their respective sections
router.include_router(legacy_router)
router.include_router(graph_router)
router.include_router(cve_router)
router.include_router(soar_router)
router.include_router(impact_router)
router.include_router(twin_router)
router.include_router(agent_router)
router.include_router(copilot_router)
