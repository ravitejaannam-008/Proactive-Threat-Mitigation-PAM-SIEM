"""
Splunk integration API endpoints.
"""

from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.services.splunk_integration import SplunkIntegration

logger = structlog.get_logger(__name__)
router = APIRouter()


class SplunkStatusResponse(BaseModel):
    """Response model for Splunk status."""
    connected: bool
    status: dict


class SplunkAlertResponse(BaseModel):
    """Response model for Splunk alerts."""
    alert_id: str
    severity: str
    alert_type: str
    description: str
    timestamp: str
    source: str
    host: Optional[str] = None
    user: Optional[str] = None
    ip_address: Optional[str] = None


@router.get("/status", response_model=SplunkStatusResponse)
async def get_splunk_status(splunk_integration: SplunkIntegration = Depends()):
    """Get Splunk connection status."""
    try:
        status = await splunk_integration.get_server_info()
        return SplunkStatusResponse(
            connected=splunk_integration.connected,
            status=status
        )
    except Exception as e:
        logger.error("Failed to get Splunk status", error=str(e))
        return SplunkStatusResponse(connected=False, status={"error": str(e)})


@router.get("/alerts", response_model=List[SplunkAlertResponse])
async def get_splunk_alerts(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    splunk_integration: SplunkIntegration = Depends()
):
    """Get threat alerts from Splunk."""
    try:
        alerts = await splunk_integration.get_threat_alerts(hours=hours)
        
        return [
            SplunkAlertResponse(
                alert_id=alert.alert_id,
                severity=alert.severity,
                alert_type=alert.alert_type,
                description=alert.description,
                timestamp=alert.timestamp.isoformat(),
                source=alert.source,
                host=alert.host,
                user=alert.user,
                ip_address=alert.ip_address
            )
            for alert in alerts
        ]
    except Exception as e:
        logger.error("Failed to get Splunk alerts", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")


@router.get("/mttr-metrics")
async def get_mttr_metrics(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    splunk_integration: SplunkIntegration = Depends()
):
    """Get MTTR metrics from Splunk."""
    try:
        metrics = await splunk_integration.get_mttr_metrics(hours=hours)
        return metrics
    except Exception as e:
        logger.error("Failed to get MTTR metrics", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get MTTR metrics: {str(e)}")


@router.post("/search")
async def search_splunk(
    query: str,
    earliest_time: str = "-1h",
    latest_time: str = "now",
    splunk_integration: SplunkIntegration = Depends()
):
    """Search for events in Splunk."""
    try:
        results = await splunk_integration.search_events(query, earliest_time, latest_time)
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error("Failed to search Splunk", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to search: {str(e)}") 