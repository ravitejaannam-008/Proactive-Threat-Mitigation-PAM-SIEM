"""
Tanium integration API endpoints.
"""

from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.services.tanium_integration import TaniumIntegration

logger = structlog.get_logger(__name__)
router = APIRouter()


class TaniumStatusResponse(BaseModel):
    """Response model for Tanium status."""
    connected: bool
    status: dict


class TaniumEndpointResponse(BaseModel):
    """Response model for Tanium endpoints."""
    endpoint_id: str
    hostname: str
    ip_address: str
    os_name: str
    os_version: str
    status: str
    last_seen: str
    groups: List[str]
    tags: List[str]


@router.get("/status", response_model=TaniumStatusResponse)
async def get_tanium_status(tanium_integration: TaniumIntegration = Depends()):
    """Get Tanium connection status."""
    try:
        status = await tanium_integration.get_server_info()
        return TaniumStatusResponse(
            connected=tanium_integration.connected,
            status=status
        )
    except Exception as e:
        logger.error("Failed to get Tanium status", error=str(e))
        return TaniumStatusResponse(connected=False, status={"error": str(e)})


@router.get("/endpoints", response_model=List[TaniumEndpointResponse])
async def get_tanium_endpoints(
    group: Optional[str] = Query(None, description="Filter by group"),
    tanium_integration: TaniumIntegration = Depends()
):
    """Get endpoints from Tanium."""
    try:
        endpoints = await tanium_integration.get_endpoints(group=group)
        
        return [
            TaniumEndpointResponse(
                endpoint_id=endpoint.endpoint_id,
                hostname=endpoint.hostname,
                ip_address=endpoint.ip_address,
                os_name=endpoint.os_name,
                os_version=endpoint.os_version,
                status=endpoint.status,
                last_seen=endpoint.last_seen.isoformat(),
                groups=endpoint.groups,
                tags=endpoint.tags
            )
            for endpoint in endpoints
        ]
    except Exception as e:
        logger.error("Failed to get Tanium endpoints", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get endpoints: {str(e)}")


@router.get("/endpoints/isolated", response_model=List[TaniumEndpointResponse])
async def get_isolated_endpoints(tanium_integration: TaniumIntegration = Depends()):
    """Get currently isolated endpoints."""
    try:
        endpoints = await tanium_integration.get_isolated_endpoints()
        
        return [
            TaniumEndpointResponse(
                endpoint_id=endpoint.endpoint_id,
                hostname=endpoint.hostname,
                ip_address=endpoint.ip_address,
                os_name=endpoint.os_name,
                os_version=endpoint.os_version,
                status=endpoint.status,
                last_seen=endpoint.last_seen.isoformat(),
                groups=endpoint.groups,
                tags=endpoint.tags
            )
            for endpoint in endpoints
        ]
    except Exception as e:
        logger.error("Failed to get isolated endpoints", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get isolated endpoints: {str(e)}")


@router.post("/isolate-endpoint/{endpoint_id}")
async def isolate_endpoint(
    endpoint_id: str,
    reason: str = "Manual endpoint isolation",
    tanium_integration: TaniumIntegration = Depends()
):
    """Isolate an endpoint."""
    try:
        success = await tanium_integration.isolate_endpoint(endpoint_id, reason)
        
        if success:
            return {"message": "Endpoint isolation initiated successfully", "endpoint_id": endpoint_id}
        else:
            raise HTTPException(status_code=500, detail="Endpoint isolation failed")
            
    except Exception as e:
        logger.error("Failed to isolate endpoint", endpoint_id=endpoint_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to isolate endpoint: {str(e)}")


@router.post("/isolate-endpoint-ip/{ip_address}")
async def isolate_endpoint_by_ip(
    ip_address: str,
    reason: str = "Manual endpoint isolation",
    tanium_integration: TaniumIntegration = Depends()
):
    """Isolate an endpoint by IP address."""
    try:
        success = await tanium_integration.isolate_endpoint_by_ip(ip_address, reason)
        
        if success:
            return {"message": "Endpoint isolation initiated successfully", "ip_address": ip_address}
        else:
            raise HTTPException(status_code=500, detail="Endpoint isolation failed")
            
    except Exception as e:
        logger.error("Failed to isolate endpoint by IP", ip_address=ip_address, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to isolate endpoint: {str(e)}")


@router.post("/deisolate-endpoint/{endpoint_id}")
async def deisolate_endpoint(
    endpoint_id: str,
    tanium_integration: TaniumIntegration = Depends()
):
    """Remove isolation from an endpoint."""
    try:
        success = await tanium_integration.deisolate_endpoint(endpoint_id)
        
        if success:
            return {"message": "Endpoint deisolation initiated successfully", "endpoint_id": endpoint_id}
        else:
            raise HTTPException(status_code=500, detail="Endpoint deisolation failed")
            
    except Exception as e:
        logger.error("Failed to deisolate endpoint", endpoint_id=endpoint_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to deisolate endpoint: {str(e)}")


@router.post("/quarantine-endpoint/{endpoint_id}")
async def quarantine_endpoint(
    endpoint_id: str,
    reason: str = "Manual endpoint quarantine",
    tanium_integration: TaniumIntegration = Depends()
):
    """Quarantine an endpoint."""
    try:
        success = await tanium_integration.quarantine_endpoint(endpoint_id, reason)
        
        if success:
            return {"message": "Endpoint quarantine initiated successfully", "endpoint_id": endpoint_id}
        else:
            raise HTTPException(status_code=500, detail="Endpoint quarantine failed")
            
    except Exception as e:
        logger.error("Failed to quarantine endpoint", endpoint_id=endpoint_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to quarantine endpoint: {str(e)}") 