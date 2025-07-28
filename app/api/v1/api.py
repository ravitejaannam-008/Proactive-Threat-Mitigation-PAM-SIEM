"""
Main API router for the PAM-SIEM integration system.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    threats,
    responses,
    cyberark,
    splunk,
    tanium,
    monitoring,
    webhooks
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(responses.router, prefix="/responses", tags=["responses"])
api_router.include_router(cyberark.router, prefix="/cyberark", tags=["cyberark"])
api_router.include_router(splunk.router, prefix="/splunk", tags=["splunk"])
api_router.include_router(tanium.router, prefix="/tanium", tags=["tanium"])
api_router.include_router(monitoring.router, prefix="/monitoring", tags=["monitoring"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"]) 