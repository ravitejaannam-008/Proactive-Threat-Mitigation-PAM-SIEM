"""
Monitoring and metrics configuration for the PAM-SIEM integration system.
"""

import time
from typing import Dict, Any

import structlog
from prometheus_client import Counter, Histogram, Gauge, Summary

logger = structlog.get_logger(__name__)


# Prometheus metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status"]
)

REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"]
)

RESPONSE_SIZE = Histogram(
    "http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "endpoint"]
)

ACTIVE_CONNECTIONS = Gauge(
    "http_active_connections",
    "Number of active HTTP connections"
)

THREAT_DETECTION_COUNT = Counter(
    "threat_detections_total",
    "Total number of threat detections",
    ["source", "severity", "type"]
)

RESPONSE_ACTION_COUNT = Counter(
    "response_actions_total",
    "Total number of response actions taken",
    ["action_type", "status"]
)

MTTR_HISTOGRAM = Histogram(
    "mttr_seconds",
    "Mean Time To Respond in seconds",
    ["threat_type"]
)

SYSTEM_HEALTH = Gauge(
    "system_health",
    "System health status (1=healthy, 0=unhealthy)"
)

CYBERARK_CONNECTION_STATUS = Gauge(
    "cyberark_connection_status",
    "CyberArk PTA connection status (1=connected, 0=disconnected)"
)

SPLUNK_CONNECTION_STATUS = Gauge(
    "splunk_connection_status",
    "Splunk connection status (1=connected, 0=disconnected)"
)

TANIUM_CONNECTION_STATUS = Gauge(
    "tanium_connection_status",
    "Tanium connection status (1=connected, 0=disconnected)"
)

CREDENTIAL_ROTATION_COUNT = Counter(
    "credential_rotations_total",
    "Total number of credential rotations",
    ["status", "account_type"]
)

SESSION_ISOLATION_COUNT = Counter(
    "session_isolations_total",
    "Total number of session isolations",
    ["status", "endpoint_type"]
)

WEBHOOK_PROCESSING_TIME = Histogram(
    "webhook_processing_time_seconds",
    "Time taken to process webhooks",
    ["source", "type"]
)

ALERT_PROCESSING_TIME = Histogram(
    "alert_processing_time_seconds",
    "Time taken to process alerts",
    ["source", "severity"]
)


class MetricsCollector:
    """Collector for application metrics."""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_times = []
        self.response_times = []
    
    def record_request(self, method: str, endpoint: str, status: int, duration: float, size: int = 0):
        """Record HTTP request metrics."""
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
        REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)
        
        if size > 0:
            RESPONSE_SIZE.labels(method=method, endpoint=endpoint).observe(size)
        
        self.request_times.append(duration)
    
    def record_threat_detection(self, source: str, severity: str, threat_type: str):
        """Record threat detection metrics."""
        THREAT_DETECTION_COUNT.labels(
            source=source, 
            severity=severity, 
            type=threat_type
        ).inc()
    
    def record_response_action(self, action_type: str, status: str):
        """Record response action metrics."""
        RESPONSE_ACTION_COUNT.labels(
            action_type=action_type, 
            status=status
        ).inc()
    
    def record_mttr(self, threat_type: str, response_time: float):
        """Record Mean Time To Respond metrics."""
        MTTR_HISTOGRAM.labels(threat_type=threat_type).observe(response_time)
    
    def set_system_health(self, healthy: bool):
        """Set system health status."""
        SYSTEM_HEALTH.set(1 if healthy else 0)
    
    def set_cyberark_status(self, connected: bool):
        """Set CyberArk connection status."""
        CYBERARK_CONNECTION_STATUS.set(1 if connected else 0)
    
    def set_splunk_status(self, connected: bool):
        """Set Splunk connection status."""
        SPLUNK_CONNECTION_STATUS.set(1 if connected else 0)
    
    def set_tanium_status(self, connected: bool):
        """Set Tanium connection status."""
        TANIUM_CONNECTION_STATUS.set(1 if connected else 0)
    
    def record_credential_rotation(self, status: str, account_type: str):
        """Record credential rotation metrics."""
        CREDENTIAL_ROTATION_COUNT.labels(
            status=status, 
            account_type=account_type
        ).inc()
    
    def record_session_isolation(self, status: str, endpoint_type: str):
        """Record session isolation metrics."""
        SESSION_ISOLATION_COUNT.labels(
            status=status, 
            endpoint_type=endpoint_type
        ).inc()
    
    def record_webhook_processing(self, source: str, webhook_type: str, duration: float):
        """Record webhook processing metrics."""
        WEBHOOK_PROCESSING_TIME.labels(
            source=source, 
            type=webhook_type
        ).observe(duration)
    
    def record_alert_processing(self, source: str, severity: str, duration: float):
        """Record alert processing metrics."""
        ALERT_PROCESSING_TIME.labels(
            source=source, 
            severity=severity
        ).observe(duration)
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        uptime = time.time() - self.start_time
        
        return {
            "uptime_seconds": uptime,
            "uptime_formatted": self._format_uptime(uptime),
            "total_requests": len(self.request_times),
            "avg_request_time": sum(self.request_times) / len(self.request_times) if self.request_times else 0,
            "total_response_time": sum(self.response_times) / len(self.response_times) if self.response_times else 0,
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format."""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


# Global metrics collector instance
metrics_collector = MetricsCollector()


def setup_monitoring():
    """Setup monitoring and metrics collection."""
    logger.info("Setting up monitoring and metrics collection")
    
    # Initialize system health
    metrics_collector.set_system_health(True)
    
    # Initialize connection statuses
    metrics_collector.set_cyberark_status(False)
    metrics_collector.set_splunk_status(False)
    metrics_collector.set_tanium_status(False)
    
    logger.info("Monitoring setup completed") 