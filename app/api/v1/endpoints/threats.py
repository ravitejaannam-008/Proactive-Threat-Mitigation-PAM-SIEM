"""
Threat detection and management API endpoints.
"""

from datetime import datetime
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.monitoring import metrics_collector
from app.models.threat import ThreatDetection, ThreatSeverity, ThreatType
from app.services.response_engine import ResponseEngine
from app.services.cyberark_integration import CyberArkPTA

logger = structlog.get_logger(__name__)
router = APIRouter()


class ThreatDetectionRequest(BaseModel):
    """Request model for threat detection."""
    source: str
    severity: ThreatSeverity
    threat_type: ThreatType
    description: str
    affected_accounts: Optional[List[str]] = None
    affected_endpoints: Optional[List[str]] = None
    evidence: Optional[dict] = None
    timestamp: Optional[datetime] = None


class ThreatDetectionResponse(BaseModel):
    """Response model for threat detection."""
    id: str
    source: str
    severity: ThreatSeverity
    threat_type: ThreatType
    description: str
    status: str
    created_at: datetime
    response_actions: List[str] = []
    mttr_seconds: Optional[float] = None


class ThreatListResponse(BaseModel):
    """Response model for threat list."""
    threats: List[ThreatDetectionResponse]
    total: int
    page: int
    page_size: int


@router.post("/detect", response_model=ThreatDetectionResponse)
async def detect_threat(
    threat: ThreatDetectionRequest,
    response_engine: ResponseEngine = Depends()
):
    """
    Detect and process a new threat.
    
    This endpoint receives threat detections from various sources (CyberArk PTA, Splunk, etc.)
    and initiates automated response actions.
    """
    try:
        start_time = datetime.now()
        
        logger.info(
            "Processing threat detection",
            source=threat.source,
            severity=threat.severity,
            threat_type=threat.threat_type,
            description=threat.description
        )
        
        # Record threat detection metrics
        metrics_collector.record_threat_detection(
            source=threat.source,
            severity=threat.severity.value,
            threat_type=threat.threat_type.value
        )
        
        # Process threat through response engine
        threat_id = await response_engine.process_threat(threat)
        
        # Calculate MTTR
        end_time = datetime.now()
        mttr_seconds = (end_time - start_time).total_seconds()
        
        # Record MTTR metrics
        metrics_collector.record_mttr(
            threat_type=threat.threat_type.value,
            response_time=mttr_seconds
        )
        
        # Get threat details
        threat_details = await response_engine.get_threat_details(threat_id)
        
        logger.info(
            "Threat detection processed successfully",
            threat_id=threat_id,
            mttr_seconds=mttr_seconds,
            response_actions=threat_details.get("response_actions", [])
        )
        
        return ThreatDetectionResponse(
            id=threat_id,
            source=threat.source,
            severity=threat.severity,
            threat_type=threat.threat_type,
            description=threat.description,
            status=threat_details.get("status", "processing"),
            created_at=start_time,
            response_actions=threat_details.get("response_actions", []),
            mttr_seconds=mttr_seconds
        )
        
    except Exception as e:
        logger.error(
            "Failed to process threat detection",
            error=str(e),
            source=threat.source,
            severity=threat.severity,
            threat_type=threat.threat_type,
            exc_info=True
        )
        raise HTTPException(status_code=500, detail=f"Failed to process threat: {str(e)}")


@router.get("/", response_model=ThreatListResponse)
async def list_threats(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    severity: Optional[ThreatSeverity] = Query(None, description="Filter by severity"),
    threat_type: Optional[ThreatType] = Query(None, description="Filter by threat type"),
    source: Optional[str] = Query(None, description="Filter by source"),
    status: Optional[str] = Query(None, description="Filter by status"),
    response_engine: ResponseEngine = Depends()
):
    """
    List all threats with optional filtering and pagination.
    """
    try:
        threats, total = await response_engine.list_threats(
            page=page,
            page_size=page_size,
            severity=severity,
            threat_type=threat_type,
            source=source,
            status=status
        )
        
        return ThreatListResponse(
            threats=threats,
            total=total,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error("Failed to list threats", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to list threats: {str(e)}")


@router.get("/{threat_id}", response_model=ThreatDetectionResponse)
async def get_threat(
    threat_id: str,
    response_engine: ResponseEngine = Depends()
):
    """
    Get detailed information about a specific threat.
    """
    try:
        threat = await response_engine.get_threat_details(threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        return ThreatDetectionResponse(**threat)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get threat details", threat_id=threat_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get threat details: {str(e)}")


@router.post("/{threat_id}/acknowledge")
async def acknowledge_threat(
    threat_id: str,
    response_engine: ResponseEngine = Depends()
):
    """
    Acknowledge a threat (mark as reviewed by security team).
    """
    try:
        await response_engine.acknowledge_threat(threat_id)
        
        logger.info("Threat acknowledged", threat_id=threat_id)
        
        return {"message": "Threat acknowledged successfully", "threat_id": threat_id}
        
    except Exception as e:
        logger.error("Failed to acknowledge threat", threat_id=threat_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to acknowledge threat: {str(e)}")


@router.post("/{threat_id}/escalate")
async def escalate_threat(
    threat_id: str,
    response_engine: ResponseEngine = Depends()
):
    """
    Escalate a threat to manual review.
    """
    try:
        await response_engine.escalate_threat(threat_id)
        
        logger.info("Threat escalated", threat_id=threat_id)
        
        return {"message": "Threat escalated successfully", "threat_id": threat_id}
        
    except Exception as e:
        logger.error("Failed to escalate threat", threat_id=threat_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to escalate threat: {str(e)}")


@router.get("/stats/summary")
async def get_threat_stats():
    """
    Get threat detection statistics.
    """
    try:
        # Get metrics from Prometheus
        stats = {
            "total_detections": metrics_collector.get_system_stats(),
            "severity_distribution": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "source_distribution": {},
            "threat_type_distribution": {},
            "avg_mttr_seconds": 0
        }
        
        return stats
        
    except Exception as e:
        logger.error("Failed to get threat stats", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get threat stats: {str(e)}") 