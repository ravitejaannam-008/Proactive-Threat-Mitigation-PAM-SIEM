"""
Webhook endpoints for receiving alerts from external systems.
"""

import hmac
import hashlib
import time
from typing import Dict, Any

import structlog
from fastapi import APIRouter, Request, HTTPException, Header, Depends
from pydantic import BaseModel

from app.core.config import settings
from app.core.monitoring import metrics_collector
from app.models.threat import ThreatDetection, ThreatSeverity, ThreatType, ThreatSource
from app.services.response_engine import ResponseEngine

logger = structlog.get_logger(__name__)
router = APIRouter()


class WebhookPayload(BaseModel):
    """Base webhook payload model."""
    pass


class SplunkWebhookPayload(WebhookPayload):
    """Splunk webhook payload model."""
    results: list
    search_name: str
    app: str
    owner: str
    results_link: str


class CyberArkWebhookPayload(WebhookPayload):
    """CyberArk webhook payload model."""
    alert_id: str
    severity: str
    alert_type: str
    description: str
    timestamp: str
    source_ip: str = None
    target_ip: str = None
    username: str = None
    account_name: str = None
    session_id: str = None


class TaniumWebhookPayload(WebhookPayload):
    """Tanium webhook payload model."""
    endpoint_id: str
    hostname: str
    ip_address: str
    alert_type: str
    description: str
    timestamp: str


def verify_webhook_signature(request_body: bytes, signature: str, secret: str) -> bool:
    """Verify webhook signature for security."""
    if not signature:
        return False
    
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        request_body,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_signature}", signature)


@router.post("/splunk")
async def splunk_webhook(
    request: Request,
    payload: SplunkWebhookPayload,
    x_splunk_signature: str = Header(None),
    response_engine: ResponseEngine = Depends()
):
    """
    Receive webhook alerts from Splunk.
    """
    try:
        start_time = time.time()
        
        # Verify webhook signature
        body = await request.body()
        if not verify_webhook_signature(body, x_splunk_signature, settings.WEBHOOK_SECRET):
            logger.warning("Invalid webhook signature from Splunk")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        logger.info("Received Splunk webhook", search_name=payload.search_name, results_count=len(payload.results))
        
        # Process each result
        for result in payload.results:
            try:
                # Extract threat information from Splunk result
                threat = ThreatDetection(
                    source=ThreatSource.SPLUNK,
                    severity=ThreatSeverity(result.get("severity", "medium")),
                    threat_type=ThreatType(result.get("threat_type", "suspicious_activity")),
                    description=result.get("description", "Threat detected via Splunk"),
                    affected_accounts=result.get("affected_accounts"),
                    affected_endpoints=result.get("affected_endpoints"),
                    evidence={
                        "splunk_result": result,
                        "search_name": payload.search_name,
                        "results_link": payload.results_link
                    },
                    detected_at=result.get("_time")
                )
                
                # Process threat
                await response_engine.process_threat(threat)
                
            except Exception as e:
                logger.error("Failed to process Splunk result", result=result, error=str(e))
        
        # Record metrics
        processing_time = time.time() - start_time
        metrics_collector.record_webhook_processing("splunk", "threat_alert", processing_time)
        
        return {"status": "success", "processed_results": len(payload.results)}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error processing Splunk webhook", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/cyberark")
async def cyberark_webhook(
    request: Request,
    payload: CyberArkWebhookPayload,
    x_cyberark_signature: str = Header(None),
    response_engine: ResponseEngine = Depends()
):
    """
    Receive webhook alerts from CyberArk PTA.
    """
    try:
        start_time = time.time()
        
        # Verify webhook signature
        body = await request.body()
        if not verify_webhook_signature(body, x_cyberark_signature, settings.WEBHOOK_SECRET):
            logger.warning("Invalid webhook signature from CyberArk")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        logger.info("Received CyberArk webhook", alert_id=payload.alert_id, severity=payload.severity)
        
        # Convert to threat detection
        threat = ThreatDetection(
            source=ThreatSource.CYBERARK_PTA,
            severity=ThreatSeverity(payload.severity),
            threat_type=ThreatType(payload.alert_type.lower()),
            description=payload.description,
            affected_accounts=[payload.account_name] if payload.account_name else None,
            affected_endpoints=[payload.target_ip] if payload.target_ip else None,
            evidence={
                "alert_id": payload.alert_id,
                "session_id": payload.session_id,
                "source_ip": payload.source_ip,
                "target_ip": payload.target_ip,
                "username": payload.username,
                "account_name": payload.account_name
            },
            detected_at=payload.timestamp
        )
        
        # Process threat
        await response_engine.process_threat(threat)
        
        # Record metrics
        processing_time = time.time() - start_time
        metrics_collector.record_webhook_processing("cyberark", "threat_alert", processing_time)
        
        return {"status": "success", "alert_id": payload.alert_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error processing CyberArk webhook", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/tanium")
async def tanium_webhook(
    request: Request,
    payload: TaniumWebhookPayload,
    x_tanium_signature: str = Header(None),
    response_engine: ResponseEngine = Depends()
):
    """
    Receive webhook alerts from Tanium.
    """
    try:
        start_time = time.time()
        
        # Verify webhook signature
        body = await request.body()
        if not verify_webhook_signature(body, x_tanium_signature, settings.WEBHOOK_SECRET):
            logger.warning("Invalid webhook signature from Tanium")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        logger.info("Received Tanium webhook", endpoint_id=payload.endpoint_id, alert_type=payload.alert_type)
        
        # Convert to threat detection
        threat = ThreatDetection(
            source=ThreatSource.TANIUM,
            severity=ThreatSeverity.HIGH,  # Tanium alerts are typically high severity
            threat_type=ThreatType(payload.alert_type.lower()),
            description=payload.description,
            affected_endpoints=[payload.ip_address],
            evidence={
                "endpoint_id": payload.endpoint_id,
                "hostname": payload.hostname,
                "ip_address": payload.ip_address,
                "alert_type": payload.alert_type
            },
            detected_at=payload.timestamp
        )
        
        # Process threat
        await response_engine.process_threat(threat)
        
        # Record metrics
        processing_time = time.time() - start_time
        metrics_collector.record_webhook_processing("tanium", "threat_alert", processing_time)
        
        return {"status": "success", "endpoint_id": payload.endpoint_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error processing Tanium webhook", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/generic")
async def generic_webhook(
    request: Request,
    payload: Dict[str, Any],
    x_webhook_signature: str = Header(None),
    response_engine: ResponseEngine = Depends()
):
    """
    Receive generic webhook alerts from any external system.
    """
    try:
        start_time = time.time()
        
        # Verify webhook signature
        body = await request.body()
        if not verify_webhook_signature(body, x_webhook_signature, settings.WEBHOOK_SECRET):
            logger.warning("Invalid webhook signature from generic source")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        logger.info("Received generic webhook", payload=payload)
        
        # Extract threat information from generic payload
        threat = ThreatDetection(
            source=ThreatSource.EXTERNAL,
            severity=ThreatSeverity(payload.get("severity", "medium")),
            threat_type=ThreatType(payload.get("threat_type", "suspicious_activity")),
            description=payload.get("description", "Threat detected via external system"),
            affected_accounts=payload.get("affected_accounts"),
            affected_endpoints=payload.get("affected_endpoints"),
            evidence=payload,
            detected_at=payload.get("timestamp")
        )
        
        # Process threat
        await response_engine.process_threat(threat)
        
        # Record metrics
        processing_time = time.time() - start_time
        metrics_collector.record_webhook_processing("generic", "threat_alert", processing_time)
        
        return {"status": "success", "threat_id": threat.id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error processing generic webhook", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/health")
async def webhook_health():
    """
    Health check endpoint for webhooks.
    """
    return {
        "status": "healthy",
        "webhook_secret_configured": bool(settings.WEBHOOK_SECRET),
        "timestamp": time.time()
    } 