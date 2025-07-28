"""
Threat detection models and enums.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatType(str, Enum):
    """Types of threats that can be detected."""
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE = "ransomware"
    APT = "apt"
    INSIDER_THREAT = "insider_threat"


class ThreatStatus(str, Enum):
    """Status of threat detection."""
    DETECTED = "detected"
    PROCESSING = "processing"
    RESPONDING = "responding"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"


class ResponseActionType(str, Enum):
    """Types of response actions."""
    CREDENTIAL_ROTATION = "credential_rotation"
    SESSION_ISOLATION = "session_isolation"
    ENDPOINT_ISOLATION = "endpoint_isolation"
    NETWORK_QUARANTINE = "network_quarantine"
    ALERT_NOTIFICATION = "alert_notification"
    MANUAL_REVIEW = "manual_review"
    THREAT_HUNTING = "threat_hunting"


class ThreatSource(str, Enum):
    """Sources of threat detections."""
    CYBERARK_PTA = "cyberark_pta"
    SPLUNK = "splunk"
    TANIUM = "tanium"
    MANUAL = "manual"
    EXTERNAL = "external"


class ThreatDetection(BaseModel):
    """Model for threat detection."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    source: ThreatSource
    severity: ThreatSeverity
    threat_type: ThreatType
    description: str
    status: ThreatStatus = ThreatStatus.DETECTED
    affected_accounts: Optional[List[str]] = None
    affected_endpoints: Optional[List[str]] = None
    affected_users: Optional[List[str]] = None
    evidence: Optional[Dict[str, Any]] = None
    indicators: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    detected_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    response_actions: List[ResponseActionType] = []
    mttr_seconds: Optional[float] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    false_positive: bool = False
    escalated: bool = False
    acknowledged: bool = False
    notes: Optional[str] = None
    
    class Config:
        use_enum_values = True


class ThreatEvidence(BaseModel):
    """Model for threat evidence."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    threat_id: str
    evidence_type: str
    source: str
    data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.now)
    confidence: float = Field(ge=0.0, le=1.0)
    verified: bool = False


class ThreatIndicator(BaseModel):
    """Model for threat indicators (IOCs)."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    threat_id: str
    indicator_type: str  # IP, domain, hash, etc.
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    source: str
    tags: List[str] = []


class ResponseAction(BaseModel):
    """Model for response actions taken."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    threat_id: str
    action_type: ResponseActionType
    status: str = "pending"  # pending, in_progress, completed, failed
    initiated_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    executed_by: Optional[str] = None


class ThreatMetrics(BaseModel):
    """Model for threat metrics and statistics."""
    total_detections: int = 0
    detections_by_severity: Dict[ThreatSeverity, int] = {}
    detections_by_type: Dict[ThreatType, int] = {}
    detections_by_source: Dict[ThreatSource, int] = {}
    avg_mttr_seconds: float = 0.0
    response_time_distribution: Dict[str, int] = {}
    false_positive_rate: float = 0.0
    containment_rate: float = 0.0
    escalation_rate: float = 0.0
    period_start: datetime
    period_end: datetime


class ThreatFilter(BaseModel):
    """Model for filtering threats."""
    severity: Optional[ThreatSeverity] = None
    threat_type: Optional[ThreatType] = None
    source: Optional[ThreatSource] = None
    status: Optional[ThreatStatus] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    affected_account: Optional[str] = None
    affected_endpoint: Optional[str] = None
    escalated: Optional[bool] = None
    acknowledged: Optional[bool] = None
    false_positive: Optional[bool] = None 