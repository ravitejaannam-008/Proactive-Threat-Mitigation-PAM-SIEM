"""
Response Engine for automated threat response and playbook execution.

This service orchestrates:
- Automated playbook execution
- Cross-platform coordination
- Incident containment logic
- Response action management
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from uuid import uuid4

import structlog
from pydantic import BaseModel

from app.core.config import settings
from app.core.monitoring import metrics_collector
from app.models.threat import (
    ThreatDetection, ThreatSeverity, ThreatType, ThreatStatus, 
    ResponseActionType, ThreatSource
)
from app.services.cyberark_integration import CyberArkPTA
from app.services.splunk_integration import SplunkIntegration
from app.services.tanium_integration import TaniumIntegration

logger = structlog.get_logger(__name__)


class ResponsePlaybook(BaseModel):
    """Model for response playbooks."""
    playbook_id: str
    name: str
    description: str
    triggers: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    enabled: bool = True
    created_at: datetime
    updated_at: datetime


class ResponseAction(BaseModel):
    """Model for response actions."""
    action_id: str
    threat_id: str
    action_type: ResponseActionType
    status: str = "pending"
    initiated_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    executed_by: str = "automated"


class ResponseEngine:
    """Response Engine for automated threat response."""
    
    def __init__(self, 
                 cyberark_pta: CyberArkPTA,
                 splunk_integration: SplunkIntegration,
                 tanium_integration: TaniumIntegration):
        self.cyberark_pta = cyberark_pta
        self.splunk_integration = splunk_integration
        self.tanium_integration = tanium_integration
        
        # In-memory storage (in production, use database)
        self.threats: Dict[str, ThreatDetection] = {}
        self.response_actions: Dict[str, ResponseAction] = {}
        self.playbooks: Dict[str, ResponsePlaybook] = {}
        
        # Monitoring tasks
        self.monitoring_tasks: List[asyncio.Task] = []
        self.running = False
        
        # Initialize default playbooks
        self._initialize_default_playbooks()
    
    async def initialize(self):
        """Initialize the response engine."""
        try:
            logger.info("Initializing Response Engine")
            
            # Setup Splunk dashboard
            await self.splunk_integration.setup_threat_dashboard()
            
            # Setup webhook alerts
            await self._setup_webhook_alerts()
            
            self.running = True
            logger.info("Response Engine initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize Response Engine", error=str(e), exc_info=True)
            raise
    
    async def shutdown(self):
        """Shutdown the response engine."""
        try:
            self.running = False
            
            # Cancel monitoring tasks
            for task in self.monitoring_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            if self.monitoring_tasks:
                await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
            
            logger.info("Response Engine shutdown completed")
            
        except Exception as e:
            logger.error("Error during Response Engine shutdown", error=str(e))
    
    def _initialize_default_playbooks(self):
        """Initialize default response playbooks."""
        # Credential Theft Playbook
        credential_theft_playbook = ResponsePlaybook(
            playbook_id="credential_theft_response",
            name="Credential Theft Response",
            description="Automated response to credential theft incidents",
            triggers=[
                {"threat_type": ThreatType.CREDENTIAL_THEFT, "severity": [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]},
                {"source": ThreatSource.CYBERARK_PTA, "alert_type": "CredentialTheft"}
            ],
            actions=[
                {"type": ResponseActionType.CREDENTIAL_ROTATION, "priority": 1},
                {"type": ResponseActionType.SESSION_ISOLATION, "priority": 2},
                {"type": ResponseActionType.ALERT_NOTIFICATION, "priority": 3}
            ],
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Lateral Movement Playbook
        lateral_movement_playbook = ResponsePlaybook(
            playbook_id="lateral_movement_response",
            name="Lateral Movement Response",
            description="Automated response to lateral movement attempts",
            triggers=[
                {"threat_type": ThreatType.LATERAL_MOVEMENT, "severity": [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]},
                {"source": ThreatSource.CYBERARK_PTA, "alert_type": "LateralMovement"}
            ],
            actions=[
                {"type": ResponseActionType.SESSION_ISOLATION, "priority": 1},
                {"type": ResponseActionType.ENDPOINT_ISOLATION, "priority": 2},
                {"type": ResponseActionType.ALERT_NOTIFICATION, "priority": 3}
            ],
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Critical Threat Playbook
        critical_threat_playbook = ResponsePlaybook(
            playbook_id="critical_threat_response",
            name="Critical Threat Response",
            description="Comprehensive response to critical threats",
            triggers=[
                {"severity": ThreatSeverity.CRITICAL}
            ],
            actions=[
                {"type": ResponseActionType.CREDENTIAL_ROTATION, "priority": 1},
                {"type": ResponseActionType.SESSION_ISOLATION, "priority": 1},
                {"type": ResponseActionType.ENDPOINT_ISOLATION, "priority": 2},
                {"type": ResponseActionType.NETWORK_QUARANTINE, "priority": 2},
                {"type": ResponseActionType.ALERT_NOTIFICATION, "priority": 3},
                {"type": ResponseActionType.MANUAL_REVIEW, "priority": 4}
            ],
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.playbooks = {
            credential_theft_playbook.playbook_id: credential_theft_playbook,
            lateral_movement_playbook.playbook_id: lateral_movement_playbook,
            critical_threat_playbook.playbook_id: critical_threat_playbook
        }
        
        logger.info("Default playbooks initialized", count=len(self.playbooks))
    
    async def _setup_webhook_alerts(self):
        """Setup webhook alerts in Splunk."""
        try:
            # Setup webhook for high-severity threats
            webhook_url = f"http://{settings.HOST}:{settings.PORT}/api/v1/webhooks/splunk"
            
            await self.splunk_integration.create_webhook_alert(
                name="High_Severity_Threat_Webhook",
                search_query=f'index="{settings.SPLUNK_INDEX}" sourcetype="threat_alert" severity="high" OR severity="critical"',
                webhook_url=webhook_url,
                conditions={"count": 1}
            )
            
            logger.info("Webhook alerts configured successfully")
            
        except Exception as e:
            logger.error("Failed to setup webhook alerts", error=str(e))
    
    async def process_threat(self, threat: ThreatDetection) -> str:
        """Process a new threat detection."""
        try:
            # Store threat
            self.threats[threat.id] = threat
            
            # Send to Splunk
            await self.splunk_integration.send_threat_event(threat)
            
            # Determine appropriate playbook
            playbook = self._select_playbook(threat)
            
            if playbook and settings.AUTO_RESPONSE_ENABLED:
                # Execute playbook
                await self._execute_playbook(threat, playbook)
            else:
                # Manual review required
                threat.status = ThreatStatus.ESCALATED
                logger.info("Threat escalated for manual review", threat_id=threat.id)
            
            return threat.id
            
        except Exception as e:
            logger.error("Failed to process threat", threat_id=threat.id, error=str(e), exc_info=True)
            raise
    
    def _select_playbook(self, threat: ThreatDetection) -> Optional[ResponsePlaybook]:
        """Select the appropriate playbook for a threat."""
        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue
            
            for trigger in playbook.triggers:
                if self._matches_trigger(threat, trigger):
                    logger.info("Playbook selected", playbook_id=playbook.playbook_id, threat_id=threat.id)
                    return playbook
        
        return None
    
    def _matches_trigger(self, threat: ThreatDetection, trigger: Dict[str, Any]) -> bool:
        """Check if a threat matches a trigger condition."""
        # Check threat type
        if "threat_type" in trigger:
            if threat.threat_type != trigger["threat_type"]:
                return False
        
        # Check severity
        if "severity" in trigger:
            severities = trigger["severity"]
            if isinstance(severities, list):
                if threat.severity not in severities:
                    return False
            else:
                if threat.severity != severities:
                    return False
        
        # Check source
        if "source" in trigger:
            if threat.source != trigger["source"]:
                return False
        
        # Check alert type (for CyberArk)
        if "alert_type" in trigger and threat.evidence:
            if threat.evidence.get("alert_type") != trigger["alert_type"]:
                return False
        
        return True
    
    async def _execute_playbook(self, threat: ThreatDetection, playbook: ResponsePlaybook):
        """Execute a response playbook."""
        try:
            logger.info("Executing playbook", playbook_id=playbook.playbook_id, threat_id=threat.id)
            
            # Sort actions by priority
            sorted_actions = sorted(playbook.actions, key=lambda x: x.get("priority", 999))
            
            # Execute actions
            for action_config in sorted_actions:
                action_type = action_config["type"]
                
                try:
                    await self._execute_action(threat, action_type)
                    
                    # Add action to threat
                    threat.response_actions.append(action_type)
                    
                except Exception as e:
                    logger.error("Action execution failed", 
                               threat_id=threat.id, 
                               action_type=action_type, 
                               error=str(e))
            
            # Update threat status
            threat.status = ThreatStatus.CONTAINED
            
            logger.info("Playbook execution completed", playbook_id=playbook.playbook_id, threat_id=threat.id)
            
        except Exception as e:
            logger.error("Playbook execution failed", playbook_id=playbook.playbook_id, threat_id=threat.id, error=str(e))
            threat.status = ThreatStatus.ESCALATED
    
    async def _execute_action(self, threat: ThreatDetection, action_type: ResponseActionType):
        """Execute a specific response action."""
        action_id = str(uuid4())
        start_time = datetime.now()
        
        action = ResponseAction(
            action_id=action_id,
            threat_id=threat.id,
            action_type=action_type,
            initiated_at=start_time
        )
        
        self.response_actions[action_id] = action
        
        try:
            logger.info("Executing action", action_id=action_id, action_type=action_type, threat_id=threat.id)
            
            if action_type == ResponseActionType.CREDENTIAL_ROTATION:
                await self._execute_credential_rotation(threat, action)
            
            elif action_type == ResponseActionType.SESSION_ISOLATION:
                await self._execute_session_isolation(threat, action)
            
            elif action_type == ResponseActionType.ENDPOINT_ISOLATION:
                await self._execute_endpoint_isolation(threat, action)
            
            elif action_type == ResponseActionType.NETWORK_QUARANTINE:
                await self._execute_network_quarantine(threat, action)
            
            elif action_type == ResponseActionType.ALERT_NOTIFICATION:
                await self._execute_alert_notification(threat, action)
            
            elif action_type == ResponseActionType.MANUAL_REVIEW:
                await self._execute_manual_review(threat, action)
            
            else:
                raise ValueError(f"Unknown action type: {action_type}")
            
            # Mark action as completed
            action.status = "completed"
            action.completed_at = datetime.now()
            action.duration_seconds = (action.completed_at - action.initiated_at).total_seconds()
            
            logger.info("Action completed successfully", action_id=action_id, action_type=action_type)
            
        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            action.completed_at = datetime.now()
            action.duration_seconds = (action.completed_at - action.initiated_at).total_seconds()
            
            logger.error("Action failed", action_id=action_id, action_type=action_type, error=str(e))
            raise
    
    async def _execute_credential_rotation(self, threat: ThreatDetection, action: ResponseAction):
        """Execute credential rotation action."""
        if not settings.CREDENTIAL_ROTATION_ENABLED:
            logger.info("Credential rotation disabled, skipping", threat_id=threat.id)
            return
        
        if threat.affected_accounts:
            for account_name in threat.affected_accounts:
                try:
                    # Get account info from CyberArk
                    account_info = await self.cyberark_pta.get_account_info(account_name)
                    
                    if account_info:
                        # Rotate credential
                        success = await self.cyberark_pta.rotate_credential(
                            account_info.account_id,
                            f"Security threat detected: {threat.description}"
                        )
                        
                        if success:
                            action.details = action.details or {}
                            action.details["rotated_accounts"] = action.details.get("rotated_accounts", [])
                            action.details["rotated_accounts"].append(account_name)
                    
                except Exception as e:
                    logger.error("Failed to rotate credential for account", 
                               account_name=account_name, 
                               threat_id=threat.id, 
                               error=str(e))
    
    async def _execute_session_isolation(self, threat: ThreatDetection, action: ResponseAction):
        """Execute session isolation action."""
        if not settings.SESSION_ISOLATION_ENABLED:
            logger.info("Session isolation disabled, skipping", threat_id=threat.id)
            return
        
        if threat.evidence and threat.evidence.get("session_id"):
            session_id = threat.evidence["session_id"]
            
            try:
                success = await self.cyberark_pta.isolate_session(
                    session_id,
                    f"Security threat detected: {threat.description}"
                )
                
                if success:
                    action.details = {"isolated_session_id": session_id}
                
            except Exception as e:
                logger.error("Failed to isolate session", 
                           session_id=session_id, 
                           threat_id=threat.id, 
                           error=str(e))
    
    async def _execute_endpoint_isolation(self, threat: ThreatDetection, action: ResponseAction):
        """Execute endpoint isolation action."""
        if threat.affected_endpoints:
            for endpoint_ip in threat.affected_endpoints:
                try:
                    success = await self.tanium_integration.isolate_endpoint_by_ip(
                        endpoint_ip,
                        f"Security threat detected: {threat.description}"
                    )
                    
                    if success:
                        action.details = action.details or {}
                        action.details["isolated_endpoints"] = action.details.get("isolated_endpoints", [])
                        action.details["isolated_endpoints"].append(endpoint_ip)
                
                except Exception as e:
                    logger.error("Failed to isolate endpoint", 
                               endpoint_ip=endpoint_ip, 
                               threat_id=threat.id, 
                               error=str(e))
    
    async def _execute_network_quarantine(self, threat: ThreatDetection, action: ResponseAction):
        """Execute network quarantine action."""
        if threat.affected_endpoints:
            for endpoint_ip in threat.affected_endpoints:
                try:
                    # Get endpoint by IP
                    endpoint = await self.tanium_integration.get_endpoint_by_ip(endpoint_ip)
                    
                    if endpoint:
                        success = await self.tanium_integration.quarantine_endpoint(
                            endpoint.endpoint_id,
                            f"Security threat detected: {threat.description}"
                        )
                        
                        if success:
                            action.details = action.details or {}
                            action.details["quarantined_endpoints"] = action.details.get("quarantined_endpoints", [])
                            action.details["quarantined_endpoints"].append(endpoint_ip)
                
                except Exception as e:
                    logger.error("Failed to quarantine endpoint", 
                               endpoint_ip=endpoint_ip, 
                               threat_id=threat.id, 
                               error=str(e))
    
    async def _execute_alert_notification(self, threat: ThreatDetection, action: ResponseAction):
        """Execute alert notification action."""
        # This would typically send emails, Slack messages, etc.
        # For now, just log the notification
        logger.info("Alert notification sent", 
                   threat_id=threat.id, 
                   severity=threat.severity, 
                   threat_type=threat.threat_type)
        
        action.details = {
            "notification_sent": True,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _execute_manual_review(self, threat: ThreatDetection, action: ResponseAction):
        """Execute manual review action."""
        threat.status = ThreatStatus.ESCALATED
        threat.escalated = True
        
        action.details = {
            "escalated": True,
            "escalation_reason": "Manual review required",
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info("Threat escalated for manual review", threat_id=threat.id)
    
    async def get_threat_details(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a threat."""
        threat = self.threats.get(threat_id)
        if not threat:
            return None
        
        # Get related actions
        actions = [action for action in self.response_actions.values() if action.threat_id == threat_id]
        
        return {
            "id": threat.id,
            "source": threat.source.value,
            "severity": threat.severity.value,
            "threat_type": threat.threat_type.value,
            "description": threat.description,
            "status": threat.status.value,
            "affected_accounts": threat.affected_accounts,
            "affected_endpoints": threat.affected_endpoints,
            "created_at": threat.created_at.isoformat(),
            "detected_at": threat.detected_at.isoformat() if threat.detected_at else None,
            "mttr_seconds": threat.mttr_seconds,
            "confidence_score": threat.confidence_score,
            "evidence": threat.evidence,
            "response_actions": [action.value for action in threat.response_actions],
            "actions": [
                {
                    "action_id": action.action_id,
                    "action_type": action.action_type.value,
                    "status": action.status,
                    "initiated_at": action.initiated_at.isoformat(),
                    "completed_at": action.completed_at.isoformat() if action.completed_at else None,
                    "duration_seconds": action.duration_seconds,
                    "details": action.details,
                    "error_message": action.error_message
                }
                for action in actions
            ]
        }
    
    async def list_threats(self, 
                          page: int = 1, 
                          page_size: int = 20,
                          severity: Optional[ThreatSeverity] = None,
                          threat_type: Optional[ThreatType] = None,
                          source: Optional[ThreatSource] = None,
                          status: Optional[ThreatStatus] = None) -> tuple[List[Dict[str, Any]], int]:
        """List threats with filtering and pagination."""
        threats = list(self.threats.values())
        
        # Apply filters
        if severity:
            threats = [t for t in threats if t.severity == severity]
        if threat_type:
            threats = [t for t in threats if t.threat_type == threat_type]
        if source:
            threats = [t for t in threats if t.source == source]
        if status:
            threats = [t for t in threats if t.status == status]
        
        # Sort by created_at (newest first)
        threats.sort(key=lambda t: t.created_at, reverse=True)
        
        # Pagination
        total = len(threats)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_threats = threats[start_idx:end_idx]
        
        # Convert to dict format
        threat_dicts = []
        for threat in paginated_threats:
            threat_dicts.append({
                "id": threat.id,
                "source": threat.source.value,
                "severity": threat.severity.value,
                "threat_type": threat.threat_type.value,
                "description": threat.description,
                "status": threat.status.value,
                "created_at": threat.created_at.isoformat(),
                "response_actions": [action.value for action in threat.response_actions]
            })
        
        return threat_dicts, total
    
    async def acknowledge_threat(self, threat_id: str):
        """Acknowledge a threat."""
        threat = self.threats.get(threat_id)
        if threat:
            threat.acknowledged = True
            threat.status = ThreatStatus.RESOLVED
            logger.info("Threat acknowledged", threat_id=threat_id)
    
    async def escalate_threat(self, threat_id: str):
        """Escalate a threat for manual review."""
        threat = self.threats.get(threat_id)
        if threat:
            threat.escalated = True
            threat.status = ThreatStatus.ESCALATED
            logger.info("Threat escalated", threat_id=threat_id)
    
    async def start_monitoring(self):
        """Start monitoring for threats from all sources."""
        logger.info("Starting threat monitoring")
        
        # Start CyberArk PTA monitoring
        cyberark_task = asyncio.create_task(
            self.cyberark_pta.monitor_alerts(self.process_threat)
        )
        self.monitoring_tasks.append(cyberark_task)
        
        # Start Splunk monitoring
        splunk_task = asyncio.create_task(
            self.splunk_integration.monitor_alerts(self.process_threat)
        )
        self.monitoring_tasks.append(splunk_task)
        
        logger.info("Threat monitoring started", task_count=len(self.monitoring_tasks)) 