"""
Monitoring and metrics API endpoints.
"""

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.monitoring import metrics_collector
from app.services.response_engine import ResponseEngine

logger = structlog.get_logger(__name__)
router = APIRouter()


class SystemHealthResponse(BaseModel):
    """Response model for system health."""
    status: str
    uptime: str
    version: str
    environment: str
    connections: dict


class MetricsResponse(BaseModel):
    """Response model for metrics."""
    system_stats: dict
    threat_metrics: dict
    response_metrics: dict


@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(response_engine: ResponseEngine = Depends()):
    """Get system health status."""
    try:
        system_stats = metrics_collector.get_system_stats()
        
        # Get connection statuses
        connections = {
            "cyberark_pta": metrics_collector.CYBERARK_CONNECTION_STATUS._value.get(),
            "splunk": metrics_collector.SPLUNK_CONNECTION_STATUS._value.get(),
            "tanium": metrics_collector.TANIUM_CONNECTION_STATUS._value.get()
        }
        
        # Determine overall status
        all_connected = all(connections.values())
        status = "healthy" if all_connected else "degraded"
        
        return SystemHealthResponse(
            status=status,
            uptime=system_stats["uptime_formatted"],
            version="1.0.0",
            environment="production",
            connections=connections
        )
        
    except Exception as e:
        logger.error("Failed to get system health", error=str(e), exc_info=True)
        return SystemHealthResponse(
            status="unhealthy",
            uptime="unknown",
            version="1.0.0",
            environment="production",
            connections={}
        )


@router.get("/metrics", response_model=MetricsResponse)
async def get_system_metrics(response_engine: ResponseEngine = Depends()):
    """Get system metrics."""
    try:
        # Get system stats
        system_stats = metrics_collector.get_system_stats()
        
        # Get threat metrics
        threats, total_threats = await response_engine.list_threats(page=1, page_size=1000)
        
        threat_metrics = {
            "total_threats": total_threats,
            "threats_by_severity": {},
            "threats_by_type": {},
            "threats_by_source": {},
            "avg_mttr_seconds": 0
        }
        
        # Calculate threat metrics
        for threat in threats:
            severity = threat["severity"]
            threat_type = threat["threat_type"]
            source = threat["source"]
            
            threat_metrics["threats_by_severity"][severity] = threat_metrics["threats_by_severity"].get(severity, 0) + 1
            threat_metrics["threats_by_type"][threat_type] = threat_metrics["threats_by_type"].get(threat_type, 0) + 1
            threat_metrics["threats_by_source"][source] = threat_metrics["threats_by_source"].get(source, 0) + 1
        
        # Get response metrics
        actions = list(response_engine.response_actions.values())
        
        response_metrics = {
            "total_actions": len(actions),
            "completed_actions": len([a for a in actions if a.status == "completed"]),
            "failed_actions": len([a for a in actions if a.status == "failed"]),
            "pending_actions": len([a for a in actions if a.status == "pending"]),
            "actions_by_type": {},
            "avg_action_duration": 0
        }
        
        # Calculate response metrics
        for action in actions:
            action_type = action.action_type.value
            response_metrics["actions_by_type"][action_type] = response_metrics["actions_by_type"].get(action_type, 0) + 1
        
        # Calculate average action duration
        completed_actions = [a for a in actions if a.duration_seconds is not None]
        if completed_actions:
            response_metrics["avg_action_duration"] = sum(a.duration_seconds for a in completed_actions) / len(completed_actions)
        
        return MetricsResponse(
            system_stats=system_stats,
            threat_metrics=threat_metrics,
            response_metrics=response_metrics
        )
        
    except Exception as e:
        logger.error("Failed to get system metrics", error=str(e), exc_info=True)
        return MetricsResponse(
            system_stats={},
            threat_metrics={},
            response_metrics={}
        )


@router.get("/performance")
async def get_performance_metrics():
    """Get performance metrics."""
    try:
        # Get Prometheus metrics
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        metrics = generate_latest()
        
        return {
            "metrics": metrics.decode('utf-8'),
            "content_type": CONTENT_TYPE_LATEST
        }
        
    except Exception as e:
        logger.error("Failed to get performance metrics", error=str(e), exc_info=True)
        return {"error": "Failed to get performance metrics"} 