"""
CyberArk Privileged Threat Analytics (PTA) integration service.

This service handles:
- Anomaly detection and alerting
- Credential rotation automation
- Session monitoring and isolation
- Threat intelligence integration
"""

import asyncio
import json
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import aiohttp
import structlog
from pydantic import BaseModel

from app.core.config import settings
from app.core.monitoring import metrics_collector
from app.models.threat import ThreatDetection, ThreatSeverity, ThreatType, ThreatSource

logger = structlog.get_logger(__name__)


class CyberArkAlert(BaseModel):
    """Model for CyberArk PTA alerts."""
    alert_id: str
    severity: str
    alert_type: str
    description: str
    timestamp: datetime
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    username: Optional[str] = None
    account_name: Optional[str] = None
    session_id: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    risk_score: Optional[float] = None


class CredentialInfo(BaseModel):
    """Model for credential information."""
    account_id: str
    account_name: str
    username: str
    safe_name: str
    platform_id: str
    last_rotation: Optional[datetime] = None
    next_rotation: Optional[datetime] = None
    status: str = "active"


class SessionInfo(BaseModel):
    """Model for session information."""
    session_id: str
    account_id: str
    username: str
    source_ip: str
    target_ip: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "active"
    activities: List[Dict[str, Any]] = []


class CyberArkPTA:
    """CyberArk PTA integration service."""
    
    def __init__(self):
        self.base_url = settings.CYBERARK_PTA_URL
        self.username = settings.CYBERARK_PTA_USERNAME
        self.password = settings.CYBERARK_PTA_PASSWORD
        self.verify_ssl = settings.CYBERARK_PTA_VERIFY_SSL
        self.timeout = settings.CYBERARK_PTA_TIMEOUT
        self.session: Optional[aiohttp.ClientSession] = None
        self.auth_token: Optional[str] = None
        self.connected = False
        
        # SSL context
        self.ssl_context = None
        if not self.verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def initialize(self):
        """Initialize the CyberArk PTA connection."""
        try:
            logger.info("Initializing CyberArk PTA connection", url=self.base_url)
            
            # Create HTTP session
            connector = aiohttp.TCPConnector(ssl=self.ssl_context)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
            
            # Authenticate
            await self._authenticate()
            
            # Test connection
            await self._test_connection()
            
            self.connected = True
            metrics_collector.set_cyberark_status(True)
            
            logger.info("CyberArk PTA connection established successfully")
            
        except Exception as e:
            logger.error("Failed to initialize CyberArk PTA connection", error=str(e), exc_info=True)
            self.connected = False
            metrics_collector.set_cyberark_status(False)
            raise
    
    async def shutdown(self):
        """Shutdown the CyberArk PTA connection."""
        try:
            if self.session:
                await self.session.close()
            
            self.connected = False
            metrics_collector.set_cyberark_status(False)
            
            logger.info("CyberArk PTA connection closed")
            
        except Exception as e:
            logger.error("Error during CyberArk PTA shutdown", error=str(e))
    
    async def _authenticate(self):
        """Authenticate with CyberArk PTA."""
        try:
            auth_url = urljoin(self.base_url, "/api/auth/Logon")
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            async with self.session.post(auth_url, json=auth_data) as response:
                if response.status == 200:
                    auth_response = await response.json()
                    self.auth_token = auth_response.get("CyberArkLogonResult")
                    
                    if not self.auth_token:
                        raise Exception("No authentication token received")
                    
                    logger.info("CyberArk PTA authentication successful")
                else:
                    raise Exception(f"Authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error("CyberArk PTA authentication failed", error=str(e))
            raise
    
    async def _test_connection(self):
        """Test the connection to CyberArk PTA."""
        try:
            # Get system status
            status = await self.get_system_status()
            logger.info("CyberArk PTA connection test successful", status=status)
            
        except Exception as e:
            logger.error("CyberArk PTA connection test failed", error=str(e))
            raise
    
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to CyberArk PTA."""
        if not self.session or not self.auth_token:
            raise Exception("Not connected to CyberArk PTA")
        
        url = urljoin(self.base_url, endpoint)
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
        
        kwargs["headers"] = {**headers, **kwargs.get("headers", {})}
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 401:
                    # Token expired, re-authenticate
                    await self._authenticate()
                    kwargs["headers"]["Authorization"] = f"Bearer {self.auth_token}"
                    
                    # Retry request
                    async with self.session.request(method, url, **kwargs) as retry_response:
                        retry_response.raise_for_status()
                        return await retry_response.json()
                else:
                    response.raise_for_status()
                    return await response.json()
                    
        except Exception as e:
            logger.error("CyberArk PTA request failed", method=method, endpoint=endpoint, error=str(e))
            raise
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get CyberArk PTA system status."""
        return await self._make_request("GET", "/api/SystemStatus")
    
    async def get_alerts(self, 
                        severity: Optional[str] = None,
                        alert_type: Optional[str] = None,
                        limit: int = 100) -> List[CyberArkAlert]:
        """Get alerts from CyberArk PTA."""
        try:
            params = {"limit": limit}
            if severity:
                params["severity"] = severity
            if alert_type:
                params["alertType"] = alert_type
            
            response = await self._make_request("GET", "/api/Alerts", params=params)
            
            alerts = []
            for alert_data in response.get("Alerts", []):
                alert = CyberArkAlert(
                    alert_id=alert_data.get("AlertID"),
                    severity=alert_data.get("Severity", "medium"),
                    alert_type=alert_data.get("AlertType"),
                    description=alert_data.get("Description"),
                    timestamp=datetime.fromisoformat(alert_data.get("Timestamp")),
                    source_ip=alert_data.get("SourceIP"),
                    target_ip=alert_data.get("TargetIP"),
                    username=alert_data.get("Username"),
                    account_name=alert_data.get("AccountName"),
                    session_id=alert_data.get("SessionID"),
                    evidence=alert_data.get("Evidence"),
                    risk_score=alert_data.get("RiskScore")
                )
                alerts.append(alert)
            
            logger.info("Retrieved alerts from CyberArk PTA", count=len(alerts))
            return alerts
            
        except Exception as e:
            logger.error("Failed to get alerts from CyberArk PTA", error=str(e))
            raise
    
    async def get_anomalous_sessions(self, hours: int = 24) -> List[SessionInfo]:
        """Get anomalous sessions from CyberArk PTA."""
        try:
            since_time = datetime.now() - timedelta(hours=hours)
            params = {
                "since": since_time.isoformat(),
                "anomalous": "true"
            }
            
            response = await self._make_request("GET", "/api/Sessions", params=params)
            
            sessions = []
            for session_data in response.get("Sessions", []):
                session = SessionInfo(
                    session_id=session_data.get("SessionID"),
                    account_id=session_data.get("AccountID"),
                    username=session_data.get("Username"),
                    source_ip=session_data.get("SourceIP"),
                    target_ip=session_data.get("TargetIP"),
                    start_time=datetime.fromisoformat(session_data.get("StartTime")),
                    end_time=datetime.fromisoformat(session_data.get("EndTime")) if session_data.get("EndTime") else None,
                    status=session_data.get("Status", "active"),
                    activities=session_data.get("Activities", [])
                )
                sessions.append(session)
            
            logger.info("Retrieved anomalous sessions from CyberArk PTA", count=len(sessions))
            return sessions
            
        except Exception as e:
            logger.error("Failed to get anomalous sessions from CyberArk PTA", error=str(e))
            raise
    
    async def rotate_credential(self, account_id: str, reason: str = "Security threat detected") -> bool:
        """Rotate a credential in CyberArk."""
        try:
            rotation_data = {
                "AccountID": account_id,
                "Reason": reason,
                "Immediate": True
            }
            
            response = await self._make_request("POST", "/api/Accounts/Rotate", json=rotation_data)
            
            success = response.get("Success", False)
            if success:
                logger.info("Credential rotation initiated", account_id=account_id, reason=reason)
                metrics_collector.record_credential_rotation("success", "privileged")
            else:
                logger.error("Credential rotation failed", account_id=account_id, error=response.get("Error"))
                metrics_collector.record_credential_rotation("failed", "privileged")
            
            return success
            
        except Exception as e:
            logger.error("Failed to rotate credential", account_id=account_id, error=str(e))
            metrics_collector.record_credential_rotation("failed", "privileged")
            raise
    
    async def isolate_session(self, session_id: str, reason: str = "Security threat detected") -> bool:
        """Isolate a session in CyberArk."""
        try:
            isolation_data = {
                "SessionID": session_id,
                "Reason": reason,
                "Action": "Isolate"
            }
            
            response = await self._make_request("POST", "/api/Sessions/Isolate", json=isolation_data)
            
            success = response.get("Success", False)
            if success:
                logger.info("Session isolation initiated", session_id=session_id, reason=reason)
                metrics_collector.record_session_isolation("success", "privileged")
            else:
                logger.error("Session isolation failed", session_id=session_id, error=response.get("Error"))
                metrics_collector.record_session_isolation("failed", "privileged")
            
            return success
            
        except Exception as e:
            logger.error("Failed to isolate session", session_id=session_id, error=str(e))
            metrics_collector.record_session_isolation("failed", "privileged")
            raise
    
    async def get_account_info(self, account_id: str) -> Optional[CredentialInfo]:
        """Get account information from CyberArk."""
        try:
            response = await self._make_request("GET", f"/api/Accounts/{account_id}")
            
            account_data = response.get("Account")
            if account_data:
                return CredentialInfo(
                    account_id=account_data.get("AccountID"),
                    account_name=account_data.get("AccountName"),
                    username=account_data.get("Username"),
                    safe_name=account_data.get("SafeName"),
                    platform_id=account_data.get("PlatformID"),
                    last_rotation=datetime.fromisoformat(account_data.get("LastRotation")) if account_data.get("LastRotation") else None,
                    next_rotation=datetime.fromisoformat(account_data.get("NextRotation")) if account_data.get("NextRotation") else None,
                    status=account_data.get("Status", "active")
                )
            
            return None
            
        except Exception as e:
            logger.error("Failed to get account info", account_id=account_id, error=str(e))
            return None
    
    async def monitor_alerts(self, callback):
        """Monitor for new alerts and call the callback function."""
        logger.info("Starting CyberArk PTA alert monitoring")
        
        while self.connected:
            try:
                # Get recent alerts
                alerts = await self.get_alerts(limit=50)
                
                for alert in alerts:
                    # Check if this is a new high-severity alert
                    if alert.severity in ["high", "critical"]:
                        # Convert to threat detection
                        threat = ThreatDetection(
                            source=ThreatSource.CYBERARK_PTA,
                            severity=ThreatSeverity(alert.severity),
                            threat_type=self._map_alert_type_to_threat_type(alert.alert_type),
                            description=alert.description,
                            affected_accounts=[alert.account_name] if alert.account_name else None,
                            evidence={
                                "alert_id": alert.alert_id,
                                "session_id": alert.session_id,
                                "source_ip": alert.source_ip,
                                "target_ip": alert.target_ip,
                                "username": alert.username,
                                "risk_score": alert.risk_score,
                                "original_evidence": alert.evidence
                            },
                            detected_at=alert.timestamp
                        )
                        
                        # Call callback with threat
                        await callback(threat)
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error("Error in alert monitoring", error=str(e))
                await asyncio.sleep(60)  # Wait longer on error
    
    def _map_alert_type_to_threat_type(self, alert_type: str) -> ThreatType:
        """Map CyberArk alert types to threat types."""
        mapping = {
            "CredentialTheft": ThreatType.CREDENTIAL_THEFT,
            "LateralMovement": ThreatType.LATERAL_MOVEMENT,
            "PrivilegeEscalation": ThreatType.PRIVILEGE_ESCALATION,
            "SuspiciousActivity": ThreatType.SUSPICIOUS_ACTIVITY,
            "BruteForce": ThreatType.BRUTE_FORCE,
            "Malware": ThreatType.MALWARE,
            "DataExfiltration": ThreatType.DATA_EXFILTRATION,
            "Ransomware": ThreatType.RANSOMWARE,
            "APT": ThreatType.APT,
            "InsiderThreat": ThreatType.INSIDER_THREAT
        }
        
        return mapping.get(alert_type, ThreatType.SUSPICIOUS_ACTIVITY) 