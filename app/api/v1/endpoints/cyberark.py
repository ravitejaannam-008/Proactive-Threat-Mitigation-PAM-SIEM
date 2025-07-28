"""
CyberArk PTA integration API endpoints.
"""

from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.services.cyberark_integration import CyberArkPTA

logger = structlog.get_logger(__name__)
router = APIRouter()


class CyberArkStatusResponse(BaseModel):
    """Response model for CyberArk status."""
    connected: bool
    status: dict


class CyberArkAlertResponse(BaseModel):
    """Response model for CyberArk alerts."""
    alert_id: str
    severity: str
    alert_type: str
    description: str
    timestamp: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    username: Optional[str] = None
    account_name: Optional[str] = None
    session_id: Optional[str] = None


@router.get("/status", response_model=CyberArkStatusResponse)
async def get_cyberark_status(cyberark_pta: CyberArkPTA = Depends()):
    """Get CyberArk PTA connection status."""
    try:
        status = await cyberark_pta.get_system_status()
        return CyberArkStatusResponse(
            connected=cyberark_pta.connected,
            status=status
        )
    except Exception as e:
        logger.error("Failed to get CyberArk status", error=str(e))
        return CyberArkStatusResponse(connected=False, status={"error": str(e)})


@router.get("/alerts", response_model=List[CyberArkAlertResponse])
async def get_cyberark_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    limit: int = Query(50, ge=1, le=100, description="Number of alerts to retrieve"),
    cyberark_pta: CyberArkPTA = Depends()
):
    """Get alerts from CyberArk PTA."""
    try:
        alerts = await cyberark_pta.get_alerts(severity=severity, alert_type=alert_type, limit=limit)
        
        return [
            CyberArkAlertResponse(
                alert_id=alert.alert_id,
                severity=alert.severity,
                alert_type=alert.alert_type,
                description=alert.description,
                timestamp=alert.timestamp.isoformat(),
                source_ip=alert.source_ip,
                target_ip=alert.target_ip,
                username=alert.username,
                account_name=alert.account_name,
                session_id=alert.session_id
            )
            for alert in alerts
        ]
    except Exception as e:
        logger.error("Failed to get CyberArk alerts", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")


@router.post("/rotate-credential/{account_id}")
async def rotate_credential(
    account_id: str,
    reason: str = "Manual credential rotation",
    cyberark_pta: CyberArkPTA = Depends()
):
    """Rotate a credential in CyberArk."""
    try:
        success = await cyberark_pta.rotate_credential(account_id, reason)
        
        if success:
            return {"message": "Credential rotation initiated successfully", "account_id": account_id}
        else:
            raise HTTPException(status_code=500, detail="Credential rotation failed")
            
    except Exception as e:
        logger.error("Failed to rotate credential", account_id=account_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to rotate credential: {str(e)}")


@router.post("/isolate-session/{session_id}")
async def isolate_session(
    session_id: str,
    reason: str = "Manual session isolation",
    cyberark_pta: CyberArkPTA = Depends()
):
    """Isolate a session in CyberArk."""
    try:
        success = await cyberark_pta.isolate_session(session_id, reason)
        
        if success:
            return {"message": "Session isolation initiated successfully", "session_id": session_id}
        else:
            raise HTTPException(status_code=500, detail="Session isolation failed")
            
    except Exception as e:
        logger.error("Failed to isolate session", session_id=session_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to isolate session: {str(e)}") 