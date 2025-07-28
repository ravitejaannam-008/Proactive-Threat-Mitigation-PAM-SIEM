"""
Splunk integration service for SIEM functionality.

This service handles:
- Real-time threat visualization
- Custom alerting webhooks
- MTTR tracking and metrics
- Dashboard management
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


class SplunkAlert(BaseModel):
    """Model for Splunk alerts."""
    alert_id: str
    severity: str
    alert_type: str
    description: str
    timestamp: datetime
    source: str
    host: Optional[str] = None
    user: Optional[str] = None
    ip_address: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = None
    search_name: Optional[str] = None


class SplunkSearch(BaseModel):
    """Model for Splunk searches."""
    search_id: str
    search_name: str
    query: str
    status: str
    created_at: datetime
    results_count: int = 0


class SplunkDashboard(BaseModel):
    """Model for Splunk dashboard."""
    dashboard_id: str
    title: str
    description: str
    panels: List[Dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime


class SplunkIntegration:
    """Splunk integration service."""
    
    def __init__(self):
        self.host = settings.SPLUNK_HOST
        self.port = settings.SPLUNK_PORT
        self.username = settings.SPLUNK_USERNAME
        self.password = settings.SPLUNK_PASSWORD
        self.index = settings.SPLUNK_INDEX
        self.verify_ssl = settings.SPLUNK_VERIFY_SSL
        self.base_url = f"https://{self.host}:{self.port}"
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
        """Initialize the Splunk connection."""
        try:
            logger.info("Initializing Splunk connection", host=self.host, port=self.port)
            
            # Create HTTP session
            connector = aiohttp.TCPConnector(ssl=self.ssl_context)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            # Authenticate
            await self._authenticate()
            
            # Test connection
            await self._test_connection()
            
            self.connected = True
            metrics_collector.set_splunk_status(True)
            
            logger.info("Splunk connection established successfully")
            
        except Exception as e:
            logger.error("Failed to initialize Splunk connection", error=str(e), exc_info=True)
            self.connected = False
            metrics_collector.set_splunk_status(False)
            raise
    
    async def shutdown(self):
        """Shutdown the Splunk connection."""
        try:
            if self.session:
                await self.session.close()
            
            self.connected = False
            metrics_collector.set_splunk_status(False)
            
            logger.info("Splunk connection closed")
            
        except Exception as e:
            logger.error("Error during Splunk shutdown", error=str(e))
    
    async def _authenticate(self):
        """Authenticate with Splunk."""
        try:
            auth_url = urljoin(self.base_url, "/services/auth/login")
            auth_data = {
                "username": self.username,
                "password": self.password,
                "output_mode": "json"
            }
            
            async with self.session.post(auth_url, data=auth_data) as response:
                if response.status == 200:
                    auth_response = await response.json()
                    self.auth_token = auth_response.get("sessionKey")
                    
                    if not self.auth_token:
                        raise Exception("No authentication token received")
                    
                    logger.info("Splunk authentication successful")
                else:
                    raise Exception(f"Authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error("Splunk authentication failed", error=str(e))
            raise
    
    async def _test_connection(self):
        """Test the connection to Splunk."""
        try:
            # Get server info
            info = await self.get_server_info()
            logger.info("Splunk connection test successful", version=info.get("version"))
            
        except Exception as e:
            logger.error("Splunk connection test failed", error=str(e))
            raise
    
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Splunk."""
        if not self.session or not self.auth_token:
            raise Exception("Not connected to Splunk")
        
        url = urljoin(self.base_url, endpoint)
        headers = {
            "Authorization": f"Splunk {self.auth_token}",
            "Content-Type": "application/json"
        }
        
        kwargs["headers"] = {**headers, **kwargs.get("headers", {})}
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 401:
                    # Token expired, re-authenticate
                    await self._authenticate()
                    kwargs["headers"]["Authorization"] = f"Splunk {self.auth_token}"
                    
                    # Retry request
                    async with self.session.request(method, url, **kwargs) as retry_response:
                        retry_response.raise_for_status()
                        return await retry_response.json()
                else:
                    response.raise_for_status()
                    return await response.json()
                    
        except Exception as e:
            logger.error("Splunk request failed", method=method, endpoint=endpoint, error=str(e))
            raise
    
    async def get_server_info(self) -> Dict[str, Any]:
        """Get Splunk server information."""
        return await self._make_request("GET", "/services/server/info?output_mode=json")
    
    async def send_event(self, event_data: Dict[str, Any], source: str = "pam_siem", sourcetype: str = "json") -> bool:
        """Send an event to Splunk."""
        try:
            event_url = urljoin(self.base_url, "/services/receivers/simple")
            
            # Prepare event data
            event = {
                "event": event_data,
                "source": source,
                "sourcetype": sourcetype,
                "index": self.index
            }
            
            headers = {
                "Authorization": f"Splunk {self.auth_token}",
                "Content-Type": "application/json"
            }
            
            async with self.session.post(event_url, json=event, headers=headers) as response:
                if response.status == 200:
                    logger.info("Event sent to Splunk successfully", source=source, sourcetype=sourcetype)
                    return True
                else:
                    logger.error("Failed to send event to Splunk", status=response.status)
                    return False
                    
        except Exception as e:
            logger.error("Error sending event to Splunk", error=str(e))
            return False
    
    async def send_threat_event(self, threat: ThreatDetection) -> bool:
        """Send a threat detection event to Splunk."""
        try:
            event_data = {
                "threat_id": threat.id,
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
                "response_actions": [action.value for action in threat.response_actions]
            }
            
            return await self.send_event(event_data, source="threat_detection", sourcetype="threat_alert")
            
        except Exception as e:
            logger.error("Error sending threat event to Splunk", threat_id=threat.id, error=str(e))
            return False
    
    async def search_events(self, query: str, earliest_time: str = "-1h", latest_time: str = "now") -> List[Dict[str, Any]]:
        """Search for events in Splunk."""
        try:
            search_url = urljoin(self.base_url, "/services/search/jobs")
            
            search_data = {
                "search": query,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "output_mode": "json",
                "exec_mode": "oneshot"
            }
            
            response = await self._make_request("POST", "/services/search/jobs", data=search_data)
            
            results = response.get("results", [])
            logger.info("Splunk search completed", query=query, results_count=len(results))
            
            return results
            
        except Exception as e:
            logger.error("Splunk search failed", query=query, error=str(e))
            raise
    
    async def get_threat_alerts(self, hours: int = 24) -> List[SplunkAlert]:
        """Get threat alerts from Splunk."""
        try:
            query = f'index="{self.index}" sourcetype="threat_alert" | head 100'
            
            results = await self.search_events(query, earliest_time=f"-{hours}h")
            
            alerts = []
            for result in results:
                alert = SplunkAlert(
                    alert_id=result.get("threat_id", ""),
                    severity=result.get("severity", "medium"),
                    alert_type=result.get("threat_type", "unknown"),
                    description=result.get("description", ""),
                    timestamp=datetime.fromisoformat(result.get("_time", datetime.now().isoformat())),
                    source=result.get("source", "unknown"),
                    host=result.get("host"),
                    user=result.get("user"),
                    ip_address=result.get("ip_address"),
                    event_data=result,
                    search_name="threat_alerts"
                )
                alerts.append(alert)
            
            logger.info("Retrieved threat alerts from Splunk", count=len(alerts))
            return alerts
            
        except Exception as e:
            logger.error("Failed to get threat alerts from Splunk", error=str(e))
            raise
    
    async def create_dashboard(self, title: str, description: str, panels: List[Dict[str, Any]]) -> Optional[str]:
        """Create a new dashboard in Splunk."""
        try:
            dashboard_data = {
                "title": title,
                "description": description,
                "panels": panels,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            response = await self._make_request("POST", "/servicesNS/-/search/data/ui/views", json=dashboard_data)
            
            dashboard_id = response.get("sid")
            if dashboard_id:
                logger.info("Dashboard created successfully", title=title, dashboard_id=dashboard_id)
                return dashboard_id
            else:
                logger.error("Failed to create dashboard", title=title)
                return None
                
        except Exception as e:
            logger.error("Error creating dashboard", title=title, error=str(e))
            return None
    
    async def get_dashboard(self, dashboard_id: str) -> Optional[SplunkDashboard]:
        """Get dashboard information from Splunk."""
        try:
            response = await self._make_request("GET", f"/servicesNS/-/search/data/ui/views/{dashboard_id}")
            
            dashboard_data = response.get("entry", [{}])[0].get("content", {})
            
            return SplunkDashboard(
                dashboard_id=dashboard_id,
                title=dashboard_data.get("title", ""),
                description=dashboard_data.get("description", ""),
                panels=dashboard_data.get("panels", []),
                created_at=datetime.fromisoformat(dashboard_data.get("created_at", datetime.now().isoformat())),
                updated_at=datetime.fromisoformat(dashboard_data.get("updated_at", datetime.now().isoformat()))
            )
            
        except Exception as e:
            logger.error("Failed to get dashboard", dashboard_id=dashboard_id, error=str(e))
            return None
    
    async def update_dashboard(self, dashboard_id: str, updates: Dict[str, Any]) -> bool:
        """Update a dashboard in Splunk."""
        try:
            response = await self._make_request("PUT", f"/servicesNS/-/search/data/ui/views/{dashboard_id}", json=updates)
            
            success = response.get("success", False)
            if success:
                logger.info("Dashboard updated successfully", dashboard_id=dashboard_id)
            else:
                logger.error("Failed to update dashboard", dashboard_id=dashboard_id)
            
            return success
            
        except Exception as e:
            logger.error("Error updating dashboard", dashboard_id=dashboard_id, error=str(e))
            return False
    
    async def create_webhook_alert(self, name: str, search_query: str, webhook_url: str, conditions: Dict[str, Any]) -> bool:
        """Create a webhook alert in Splunk."""
        try:
            alert_data = {
                "name": name,
                "search": search_query,
                "alert_type": "webhook",
                "webhook_url": webhook_url,
                "conditions": conditions,
                "enabled": True
            }
            
            response = await self._make_request("POST", "/servicesNS/-/search/saved/searches", json=alert_data)
            
            success = response.get("success", False)
            if success:
                logger.info("Webhook alert created successfully", name=name)
            else:
                logger.error("Failed to create webhook alert", name=name)
            
            return success
            
        except Exception as e:
            logger.error("Error creating webhook alert", name=name, error=str(e))
            return False
    
    async def get_mttr_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """Get MTTR metrics from Splunk."""
        try:
            query = f'''
                index="{self.index}" sourcetype="threat_alert" 
                | eval mttr_seconds=if(isnotnull(mttr_seconds), mttr_seconds, 0)
                | stats 
                    avg(mttr_seconds) as avg_mttr,
                    min(mttr_seconds) as min_mttr,
                    max(mttr_seconds) as max_mttr,
                    count as total_threats
                | eval avg_mttr_minutes=round(avg_mttr/60, 2)
            '''
            
            results = await self.search_events(query, earliest_time=f"-{hours}h")
            
            if results:
                metrics = results[0]
                return {
                    "avg_mttr_seconds": float(metrics.get("avg_mttr", 0)),
                    "min_mttr_seconds": float(metrics.get("min_mttr", 0)),
                    "max_mttr_seconds": float(metrics.get("max_mttr", 0)),
                    "avg_mttr_minutes": float(metrics.get("avg_mttr_minutes", 0)),
                    "total_threats": int(metrics.get("total_threats", 0)),
                    "period_hours": hours
                }
            
            return {
                "avg_mttr_seconds": 0,
                "min_mttr_seconds": 0,
                "max_mttr_seconds": 0,
                "avg_mttr_minutes": 0,
                "total_threats": 0,
                "period_hours": hours
            }
            
        except Exception as e:
            logger.error("Failed to get MTTR metrics", error=str(e))
            return {
                "avg_mttr_seconds": 0,
                "min_mttr_seconds": 0,
                "max_mttr_seconds": 0,
                "avg_mttr_minutes": 0,
                "total_threats": 0,
                "period_hours": hours,
                "error": str(e)
            }
    
    async def setup_threat_dashboard(self) -> Optional[str]:
        """Setup the main threat dashboard in Splunk."""
        try:
            panels = [
                {
                    "type": "stat",
                    "title": "Total Threats (24h)",
                    "query": f'index="{self.index}" sourcetype="threat_alert" | stats count'
                },
                {
                    "type": "stat",
                    "title": "Critical Threats",
                    "query": f'index="{self.index}" sourcetype="threat_alert" severity="critical" | stats count'
                },
                {
                    "type": "stat",
                    "title": "Avg MTTR (minutes)",
                    "query": f'index="{self.index}" sourcetype="threat_alert" | eval mttr_minutes=mttr_seconds/60 | stats avg(mttr_minutes)'
                },
                {
                    "type": "chart",
                    "title": "Threats by Severity",
                    "query": f'index="{self.index}" sourcetype="threat_alert" | stats count by severity'
                },
                {
                    "type": "chart",
                    "title": "Threats by Type",
                    "query": f'index="{self.index}" sourcetype="threat_alert" | stats count by threat_type'
                },
                {
                    "type": "table",
                    "title": "Recent Threats",
                    "query": f'index="{self.index}" sourcetype="threat_alert" | head 10 | table threat_id, severity, threat_type, description, created_at'
                }
            ]
            
            dashboard_id = await self.create_dashboard(
                title="Proactive Threat Mitigation Dashboard",
                description="Real-time threat visualization and MTTR tracking",
                panels=panels
            )
            
            if dashboard_id:
                logger.info("Threat dashboard setup completed", dashboard_id=dashboard_id)
                return dashboard_id
            else:
                logger.error("Failed to setup threat dashboard")
                return None
                
        except Exception as e:
            logger.error("Error setting up threat dashboard", error=str(e))
            return None
    
    async def monitor_alerts(self, callback):
        """Monitor for new alerts and call the callback function."""
        logger.info("Starting Splunk alert monitoring")
        
        while self.connected:
            try:
                # Get recent alerts
                alerts = await self.get_threat_alerts(hours=1)  # Check last hour
                
                for alert in alerts:
                    # Check if this is a new high-severity alert
                    if alert.severity in ["high", "critical"]:
                        # Convert to threat detection
                        threat = ThreatDetection(
                            source=ThreatSource.SPLUNK,
                            severity=ThreatSeverity(alert.severity),
                            threat_type=ThreatType(alert.alert_type),
                            description=alert.description,
                            evidence={
                                "alert_id": alert.alert_id,
                                "source": alert.source,
                                "host": alert.host,
                                "user": alert.user,
                                "ip_address": alert.ip_address,
                                "event_data": alert.event_data
                            },
                            detected_at=alert.timestamp
                        )
                        
                        # Call callback with threat
                        await callback(threat)
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error("Error in Splunk alert monitoring", error=str(e))
                await asyncio.sleep(120)  # Wait longer on error 