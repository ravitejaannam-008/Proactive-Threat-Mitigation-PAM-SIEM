"""
Response management API endpoints.
"""

from datetime import datetime
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.models.threat import ResponseActionType
from app.services.response_engine import ResponseEngine

logger = structlog.get_logger(__name__)
router = APIRouter()


class ResponseActionResponse(BaseModel):
    """Response model for response actions."""
    action_id: str
    threat_id: str
    action_type: str
    status: str
    initiated_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    details: Optional[dict] = None
    error_message: Optional[str] = None


class ResponseActionListResponse(BaseModel):
    """Response model for response action list."""
    actions: List[ResponseActionResponse]
    total: int
    page: int
    page_size: int


@router.get("/", response_model=ResponseActionListResponse)
async def list_response_actions(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    action_type: Optional[ResponseActionType] = Query(None, description="Filter by action type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    threat_id: Optional[str] = Query(None, description="Filter by threat ID"),
    response_engine: ResponseEngine = Depends()
):
    """
    List response actions with optional filtering and pagination.
    """
    try:
        # Get actions from response engine
        actions = list(response_engine.response_actions.values())
        
        # Apply filters
        if action_type:
            actions = [a for a in actions if a.action_type == action_type]
        if status:
            actions = [a for a in actions if a.status == status]
        if threat_id:
            actions = [a for a in actions if a.threat_id == threat_id]
        
        # Sort by initiated_at (newest first)
        actions.sort(key=lambda a: a.initiated_at, reverse=True)
        
        # Pagination
        total = len(actions)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_actions = actions[start_idx:end_idx]
        
        # Convert to response format
        action_responses = []
        for action in paginated_actions:
            action_responses.append(ResponseActionResponse(
                action_id=action.action_id,
                threat_id=action.threat_id,
                action_type=action.action_type.value,
                status=action.status,
                initiated_at=action.initiated_at,
                completed_at=action.completed_at,
                duration_seconds=action.duration_seconds,
                details=action.details,
                error_message=action.error_message
            ))
        
        return ResponseActionListResponse(
            actions=action_responses,
            total=total,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error("Failed to list response actions", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to list response actions: {str(e)}")


@router.get("/{action_id}", response_model=ResponseActionResponse)
async def get_response_action(
    action_id: str,
    response_engine: ResponseEngine = Depends()
):
    """
    Get detailed information about a specific response action.
    """
    try:
        action = response_engine.response_actions.get(action_id)
        
        if not action:
            raise HTTPException(status_code=404, detail="Response action not found")
        
        return ResponseActionResponse(
            action_id=action.action_id,
            threat_id=action.threat_id,
            action_type=action.action_type.value,
            status=action.status,
            initiated_at=action.initiated_at,
            completed_at=action.completed_at,
            duration_seconds=action.duration_seconds,
            details=action.details,
            error_message=action.error_message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get response action", action_id=action_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get response action: {str(e)}")


@router.get("/stats/summary")
async def get_response_stats(response_engine: ResponseEngine = Depends()):
    """
    Get response action statistics.
    """
    try:
        actions = list(response_engine.response_actions.values())
        
        # Calculate statistics
        total_actions = len(actions)
        completed_actions = len([a for a in actions if a.status == "completed"])
        failed_actions = len([a for a in actions if a.status == "failed"])
        pending_actions = len([a for a in actions if a.status == "pending"])
        
        # Action type distribution
        action_type_distribution = {}
        for action in actions:
            action_type = action.action_type.value
            action_type_distribution[action_type] = action_type_distribution.get(action_type, 0) + 1
        
        # Average duration
        completed_with_duration = [a for a in actions if a.duration_seconds is not None]
        avg_duration = sum(a.duration_seconds for a in completed_with_duration) / len(completed_with_duration) if completed_with_duration else 0
        
        return {
            "total_actions": total_actions,
            "completed_actions": completed_actions,
            "failed_actions": failed_actions,
            "pending_actions": pending_actions,
            "success_rate": (completed_actions / total_actions * 100) if total_actions > 0 else 0,
            "avg_duration_seconds": avg_duration,
            "action_type_distribution": action_type_distribution
        }
        
    except Exception as e:
        logger.error("Failed to get response stats", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get response stats: {str(e)}") 