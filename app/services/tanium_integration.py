"""
Tanium integration service for endpoint management and response actions.

This service handles:
- Endpoint isolation capabilities
- Network quarantine automation
- Response action execution
- Endpoint monitoring and management
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

logger = structlog.get_logger(__name__)


class TaniumEndpoint(BaseModel):
    """Model for Tanium endpoint information."""
    endpoint_id: str
    hostname: str
    ip_address: str
    os_name: str
    os_version: str
    status: str = "online"
    last_seen: datetime
    groups: List[str] = []
    tags: List[str] = []


class TaniumAction(BaseModel):
    """Model for Tanium actions."""
    action_id: str
    action_type: str
    target_endpoints: List[str]
    parameters: Dict[str, Any]
    status: str = "pending"
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[Dict[str, Any]] = None


class TaniumQuestion(BaseModel):
    """Model for Tanium questions."""
    question_id: str
    question_text: str
    target_group: str
    status: str = "active"
    created_at: datetime
    results_count: int = 0


class TaniumIntegration:
    """Tanium integration service."""
    
    def __init__(self):
        self.server_url = settings.TANIUM_SERVER
        self.username = settings.TANIUM_USERNAME
        self.password = settings.TANIUM_PASSWORD
        self.verify_ssl = settings.TANIUM_VERIFY_SSL
        self.timeout = settings.TANIUM_TIMEOUT
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
        """Initialize the Tanium connection."""
        try:
            logger.info("Initializing Tanium connection", server_url=self.server_url)
            
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
            metrics_collector.set_tanium_status(True)
            
            logger.info("Tanium connection established successfully")
            
        except Exception as e:
            logger.error("Failed to initialize Tanium connection", error=str(e), exc_info=True)
            self.connected = False
            metrics_collector.set_tanium_status(False)
            raise
    
    async def shutdown(self):
        """Shutdown the Tanium connection."""
        try:
            if self.session:
                await self.session.close()
            
            self.connected = False
            metrics_collector.set_tanium_status(False)
            
            logger.info("Tanium connection closed")
            
        except Exception as e:
            logger.error("Error during Tanium shutdown", error=str(e))
    
    async def _authenticate(self):
        """Authenticate with Tanium."""
        try:
            auth_url = urljoin(self.server_url, "/api/v2/session/login")
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            async with self.session.post(auth_url, json=auth_data) as response:
                if response.status == 200:
                    auth_response = await response.json()
                    self.auth_token = auth_response.get("data", {}).get("session")
                    
                    if not self.auth_token:
                        raise Exception("No authentication token received")
                    
                    logger.info("Tanium authentication successful")
                else:
                    raise Exception(f"Authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error("Tanium authentication failed", error=str(e))
            raise
    
    async def _test_connection(self):
        """Test the connection to Tanium."""
        try:
            # Get server info
            info = await self.get_server_info()
            logger.info("Tanium connection test successful", version=info.get("version"))
            
        except Exception as e:
            logger.error("Tanium connection test failed", error=str(e))
            raise
    
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Tanium."""
        if not self.session or not self.auth_token:
            raise Exception("Not connected to Tanium")
        
        url = urljoin(self.server_url, endpoint)
        headers = {
            "session": self.auth_token,
            "Content-Type": "application/json"
        }
        
        kwargs["headers"] = {**headers, **kwargs.get("headers", {})}
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 401:
                    # Token expired, re-authenticate
                    await self._authenticate()
                    kwargs["headers"]["session"] = self.auth_token
                    
                    # Retry request
                    async with self.session.request(method, url, **kwargs) as retry_response:
                        retry_response.raise_for_status()
                        return await retry_response.json()
                else:
                    response.raise_for_status()
                    return await response.json()
                    
        except Exception as e:
            logger.error("Tanium request failed", method=method, endpoint=endpoint, error=str(e))
            raise
    
    async def get_server_info(self) -> Dict[str, Any]:
        """Get Tanium server information."""
        return await self._make_request("GET", "/api/v2/about")
    
    async def get_endpoints(self, group: Optional[str] = None) -> List[TaniumEndpoint]:
        """Get endpoints from Tanium."""
        try:
            params = {}
            if group:
                params["group"] = group
            
            response = await self._make_request("GET", "/api/v2/sensors", params=params)
            
            endpoints = []
            for endpoint_data in response.get("data", {}).get("sensors", []):
                endpoint = TaniumEndpoint(
                    endpoint_id=endpoint_data.get("id"),
                    hostname=endpoint_data.get("name"),
                    ip_address=endpoint_data.get("ip_address"),
                    os_name=endpoint_data.get("os_name"),
                    os_version=endpoint_data.get("os_version"),
                    status=endpoint_data.get("status", "online"),
                    last_seen=datetime.fromisoformat(endpoint_data.get("last_seen")),
                    groups=endpoint_data.get("groups", []),
                    tags=endpoint_data.get("tags", [])
                )
                endpoints.append(endpoint)
            
            logger.info("Retrieved endpoints from Tanium", count=len(endpoints))
            return endpoints
            
        except Exception as e:
            logger.error("Failed to get endpoints from Tanium", error=str(e))
            raise
    
    async def get_endpoint_by_ip(self, ip_address: str) -> Optional[TaniumEndpoint]:
        """Get endpoint information by IP address."""
        try:
            response = await self._make_request("GET", f"/api/v2/sensors/ip/{ip_address}")
            
            endpoint_data = response.get("data", {})
            if endpoint_data:
                return TaniumEndpoint(
                    endpoint_id=endpoint_data.get("id"),
                    hostname=endpoint_data.get("name"),
                    ip_address=endpoint_data.get("ip_address"),
                    os_name=endpoint_data.get("os_name"),
                    os_version=endpoint_data.get("os_version"),
                    status=endpoint_data.get("status", "online"),
                    last_seen=datetime.fromisoformat(endpoint_data.get("last_seen")),
                    groups=endpoint_data.get("groups", []),
                    tags=endpoint_data.get("tags", [])
                )
            
            return None
            
        except Exception as e:
            logger.error("Failed to get endpoint by IP", ip_address=ip_address, error=str(e))
            return None
    
    async def isolate_endpoint(self, endpoint_id: str, reason: str = "Security threat detected") -> bool:
        """Isolate an endpoint from the network."""
        try:
            isolation_data = {
                "action": "isolate",
                "targets": [endpoint_id],
                "parameters": {
                    "reason": reason,
                    "duration": 3600  # 1 hour
                }
            }
            
            response = await self._make_request("POST", "/api/v2/actions", json=isolation_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("Endpoint isolation initiated", endpoint_id=endpoint_id, reason=reason)
                metrics_collector.record_session_isolation("success", "endpoint")
            else:
                logger.error("Endpoint isolation failed", endpoint_id=endpoint_id, error=response.get("error"))
                metrics_collector.record_session_isolation("failed", "endpoint")
            
            return success
            
        except Exception as e:
            logger.error("Failed to isolate endpoint", endpoint_id=endpoint_id, error=str(e))
            metrics_collector.record_session_isolation("failed", "endpoint")
            raise
    
    async def isolate_endpoint_by_ip(self, ip_address: str, reason: str = "Security threat detected") -> bool:
        """Isolate an endpoint by IP address."""
        try:
            # Get endpoint by IP
            endpoint = await self.get_endpoint_by_ip(ip_address)
            
            if not endpoint:
                logger.error("Endpoint not found", ip_address=ip_address)
                return False
            
            # Isolate the endpoint
            return await self.isolate_endpoint(endpoint.endpoint_id, reason)
            
        except Exception as e:
            logger.error("Failed to isolate endpoint by IP", ip_address=ip_address, error=str(e))
            return False
    
    async def deisolate_endpoint(self, endpoint_id: str) -> bool:
        """Remove isolation from an endpoint."""
        try:
            deisolation_data = {
                "action": "deisolate",
                "targets": [endpoint_id]
            }
            
            response = await self._make_request("POST", "/api/v2/actions", json=deisolation_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("Endpoint deisolation initiated", endpoint_id=endpoint_id)
            else:
                logger.error("Endpoint deisolation failed", endpoint_id=endpoint_id, error=response.get("error"))
            
            return success
            
        except Exception as e:
            logger.error("Failed to deisolate endpoint", endpoint_id=endpoint_id, error=str(e))
            raise
    
    async def quarantine_endpoint(self, endpoint_id: str, reason: str = "Security threat detected") -> bool:
        """Quarantine an endpoint (more restrictive than isolation)."""
        try:
            quarantine_data = {
                "action": "quarantine",
                "targets": [endpoint_id],
                "parameters": {
                    "reason": reason,
                    "duration": 7200  # 2 hours
                }
            }
            
            response = await self._make_request("POST", "/api/v2/actions", json=quarantine_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("Endpoint quarantine initiated", endpoint_id=endpoint_id, reason=reason)
                metrics_collector.record_session_isolation("success", "quarantine")
            else:
                logger.error("Endpoint quarantine failed", endpoint_id=endpoint_id, error=response.get("error"))
                metrics_collector.record_session_isolation("failed", "quarantine")
            
            return success
            
        except Exception as e:
            logger.error("Failed to quarantine endpoint", endpoint_id=endpoint_id, error=str(e))
            metrics_collector.record_session_isolation("failed", "quarantine")
            raise
    
    async def kill_process(self, endpoint_id: str, process_name: str, reason: str = "Security threat detected") -> bool:
        """Kill a process on an endpoint."""
        try:
            kill_data = {
                "action": "kill_process",
                "targets": [endpoint_id],
                "parameters": {
                    "process_name": process_name,
                    "reason": reason
                }
            }
            
            response = await self._make_request("POST", "/api/v2/actions", json=kill_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("Process kill initiated", endpoint_id=endpoint_id, process_name=process_name, reason=reason)
            else:
                logger.error("Process kill failed", endpoint_id=endpoint_id, process_name=process_name, error=response.get("error"))
            
            return success
            
        except Exception as e:
            logger.error("Failed to kill process", endpoint_id=endpoint_id, process_name=process_name, error=str(e))
            raise
    
    async def block_ip(self, endpoint_id: str, ip_address: str, reason: str = "Security threat detected") -> bool:
        """Block an IP address on an endpoint."""
        try:
            block_data = {
                "action": "block_ip",
                "targets": [endpoint_id],
                "parameters": {
                    "ip_address": ip_address,
                    "reason": reason,
                    "duration": 3600  # 1 hour
                }
            }
            
            response = await self._make_request("POST", "/api/v2/actions", json=block_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("IP block initiated", endpoint_id=endpoint_id, ip_address=ip_address, reason=reason)
            else:
                logger.error("IP block failed", endpoint_id=endpoint_id, ip_address=ip_address, error=response.get("error"))
            
            return success
            
        except Exception as e:
            logger.error("Failed to block IP", endpoint_id=endpoint_id, ip_address=ip_address, error=str(e))
            raise
    
    async def collect_forensics(self, endpoint_id: str, reason: str = "Security threat detected") -> bool:
        """Collect forensic data from an endpoint."""
        try:
            forensics_data = {
                "action": "collect_forensics",
                "targets": [endpoint_id],
                "parameters": {
                    "reason": reason,
                    "include_memory": True,
                    "include_disk": False,
                    "include_network": True
                }
            }
            
            response = await self._make_request("POST", "/api/v2/actions", json=forensics_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("Forensic collection initiated", endpoint_id=endpoint_id, reason=reason)
            else:
                logger.error("Forensic collection failed", endpoint_id=endpoint_id, error=response.get("error"))
            
            return success
            
        except Exception as e:
            logger.error("Failed to collect forensics", endpoint_id=endpoint_id, error=str(e))
            raise
    
    async def get_action_status(self, action_id: str) -> Optional[TaniumAction]:
        """Get the status of an action."""
        try:
            response = await self._make_request("GET", f"/api/v2/actions/{action_id}")
            
            action_data = response.get("data", {})
            if action_data:
                return TaniumAction(
                    action_id=action_data.get("id"),
                    action_type=action_data.get("type"),
                    target_endpoints=action_data.get("targets", []),
                    parameters=action_data.get("parameters", {}),
                    status=action_data.get("status", "pending"),
                    created_at=datetime.fromisoformat(action_data.get("created_at")),
                    completed_at=datetime.fromisoformat(action_data.get("completed_at")) if action_data.get("completed_at") else None,
                    results=action_data.get("results")
                )
            
            return None
            
        except Exception as e:
            logger.error("Failed to get action status", action_id=action_id, error=str(e))
            return None
    
    async def ask_question(self, question_text: str, target_group: str = "all") -> Optional[str]:
        """Ask a question to endpoints."""
        try:
            question_data = {
                "question": question_text,
                "target_group": target_group,
                "expiration": 300  # 5 minutes
            }
            
            response = await self._make_request("POST", "/api/v2/questions", json=question_data)
            
            question_id = response.get("data", {}).get("id")
            if question_id:
                logger.info("Question asked successfully", question_id=question_id, question_text=question_text)
                return question_id
            else:
                logger.error("Failed to ask question", question_text=question_text)
                return None
                
        except Exception as e:
            logger.error("Error asking question", question_text=question_text, error=str(e))
            return None
    
    async def get_question_results(self, question_id: str) -> List[Dict[str, Any]]:
        """Get results from a question."""
        try:
            response = await self._make_request("GET", f"/api/v2/questions/{question_id}/results")
            
            results = response.get("data", {}).get("results", [])
            logger.info("Retrieved question results", question_id=question_id, results_count=len(results))
            
            return results
            
        except Exception as e:
            logger.error("Failed to get question results", question_id=question_id, error=str(e))
            raise
    
    async def create_endpoint_group(self, group_name: str, criteria: Dict[str, Any]) -> bool:
        """Create a new endpoint group."""
        try:
            group_data = {
                "name": group_name,
                "criteria": criteria
            }
            
            response = await self._make_request("POST", "/api/v2/groups", json=group_data)
            
            success = response.get("data", {}).get("success", False)
            if success:
                logger.info("Endpoint group created successfully", group_name=group_name)
            else:
                logger.error("Failed to create endpoint group", group_name=group_name, error=response.get("error"))
            
            return success
            
        except Exception as e:
            logger.error("Error creating endpoint group", group_name=group_name, error=str(e))
            return False
    
    async def get_isolated_endpoints(self) -> List[TaniumEndpoint]:
        """Get all currently isolated endpoints."""
        try:
            # Ask a question to find isolated endpoints
            question_text = "Get Computer Name, IP Address where Isolated equals true"
            question_id = await self.ask_question(question_text)
            
            if not question_id:
                return []
            
            # Wait a moment for results
            await asyncio.sleep(5)
            
            # Get results
            results = await self.get_question_results(question_id)
            
            isolated_endpoints = []
            for result in results:
                endpoint = TaniumEndpoint(
                    endpoint_id=result.get("Computer ID"),
                    hostname=result.get("Computer Name"),
                    ip_address=result.get("IP Address"),
                    os_name=result.get("OS Name", "Unknown"),
                    os_version=result.get("OS Version", "Unknown"),
                    status="isolated",
                    last_seen=datetime.now(),
                    groups=[],
                    tags=["isolated"]
                )
                isolated_endpoints.append(endpoint)
            
            logger.info("Retrieved isolated endpoints", count=len(isolated_endpoints))
            return isolated_endpoints
            
        except Exception as e:
            logger.error("Failed to get isolated endpoints", error=str(e))
            return [] 