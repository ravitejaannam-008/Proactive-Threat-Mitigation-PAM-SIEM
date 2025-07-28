"""
Integration tests for the PAM-SIEM system.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from app.models.threat import ThreatDetection, ThreatSeverity, ThreatType, ThreatSource
from app.services.response_engine import ResponseEngine
from app.services.cyberark_integration import CyberArkPTA
from app.services.splunk_integration import SplunkIntegration
from app.services.tanium_integration import TaniumIntegration
from app.models.response_action import ResponseActionType


@pytest.fixture
def mock_cyberark_pta():
    """Mock CyberArk PTA service."""
    mock = AsyncMock(spec=CyberArkPTA)
    mock.connected = True
    mock.initialize = AsyncMock()
    mock.shutdown = AsyncMock()
    mock.get_alerts = AsyncMock(return_value=[])
    mock.rotate_credential = AsyncMock(return_value=True)
    mock.isolate_session = AsyncMock(return_value=True)
    return mock


@pytest.fixture
def mock_splunk_integration():
    """Mock Splunk integration service."""
    mock = AsyncMock(spec=SplunkIntegration)
    mock.connected = True
    mock.initialize = AsyncMock()
    mock.shutdown = AsyncMock()
    mock.send_threat_event = AsyncMock(return_value=True)
    mock.get_threat_alerts = AsyncMock(return_value=[])
    return mock


@pytest.fixture
def mock_tanium_integration():
    """Mock Tanium integration service."""
    mock = AsyncMock(spec=TaniumIntegration)
    mock.connected = True
    mock.initialize = AsyncMock()
    mock.shutdown = AsyncMock()
    mock.isolate_endpoint_by_ip = AsyncMock(return_value=True)
    mock.quarantine_endpoint = AsyncMock(return_value=True)
    return mock


@pytest.fixture
def response_engine(mock_cyberark_pta, mock_splunk_integration, mock_tanium_integration):
    """Create a response engine with mocked dependencies."""
    return ResponseEngine(
        cyberark_pta=mock_cyberark_pta,
        splunk_integration=mock_splunk_integration,
        tanium_integration=mock_tanium_integration
    )


@pytest.mark.asyncio
async def test_threat_processing(response_engine):
    """Test threat processing workflow."""
    # Create a test threat
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.HIGH,
        threat_type=ThreatType.CREDENTIAL_THEFT,
        description="Test credential theft",
        affected_accounts=["test_account"],
        affected_endpoints=["192.168.1.100"],
        evidence={"session_id": "test_session_123"}
    )
    
    # Process the threat
    threat_id = await response_engine.process_threat(threat)
    
    # Verify threat was stored
    assert threat_id in response_engine.threats
    stored_threat = response_engine.threats[threat_id]
    assert stored_threat.description == "Test credential theft"
    assert stored_threat.severity == ThreatSeverity.HIGH
    
    # Verify response actions were created
    actions = [a for a in response_engine.response_actions.values() if a.threat_id == threat_id]
    assert len(actions) > 0
    
    # Verify Splunk integration was called
    response_engine.splunk_integration.send_threat_event.assert_called_once()


@pytest.mark.asyncio
async def test_credential_theft_playbook(response_engine):
    """Test credential theft response playbook."""
    # Create a credential theft threat
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.CRITICAL,
        threat_type=ThreatType.CREDENTIAL_THEFT,
        description="Critical credential theft detected",
        affected_accounts=["admin_account"],
        evidence={"session_id": "session_456"}
    )
    
    # Process the threat
    threat_id = await response_engine.process_threat(threat)
    
    # Verify playbook was executed
    stored_threat = response_engine.threats[threat_id]
    assert ResponseActionType.CREDENTIAL_ROTATION in stored_threat.response_actions
    assert ResponseActionType.SESSION_ISOLATION in stored_threat.response_actions
    assert ResponseActionType.ALERT_NOTIFICATION in stored_threat.response_actions


@pytest.mark.asyncio
async def test_lateral_movement_playbook(response_engine):
    """Test lateral movement response playbook."""
    # Create a lateral movement threat
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.HIGH,
        threat_type=ThreatType.LATERAL_MOVEMENT,
        description="Lateral movement detected",
        affected_endpoints=["192.168.1.100", "192.168.1.101"]
    )
    
    # Process the threat
    threat_id = await response_engine.process_threat(threat)
    
    # Verify playbook was executed
    stored_threat = response_engine.threats[threat_id]
    assert ResponseActionType.SESSION_ISOLATION in stored_threat.response_actions
    assert ResponseActionType.ENDPOINT_ISOLATION in stored_threat.response_actions


@pytest.mark.asyncio
async def test_critical_threat_playbook(response_engine):
    """Test critical threat response playbook."""
    # Create a critical threat
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.CRITICAL,
        threat_type=ThreatType.MALWARE,
        description="Critical malware detected",
        affected_endpoints=["192.168.1.100"]
    )
    
    # Process the threat
    threat_id = await response_engine.process_threat(threat)
    
    # Verify comprehensive playbook was executed
    stored_threat = response_engine.threats[threat_id]
    assert ResponseActionType.CREDENTIAL_ROTATION in stored_threat.response_actions
    assert ResponseActionType.SESSION_ISOLATION in stored_threat.response_actions
    assert ResponseActionType.ENDPOINT_ISOLATION in stored_threat.response_actions
    assert ResponseActionType.NETWORK_QUARANTINE in stored_threat.response_actions
    assert ResponseActionType.MANUAL_REVIEW in stored_threat.response_actions


@pytest.mark.asyncio
async def test_threat_listing(response_engine):
    """Test threat listing functionality."""
    # Create multiple threats
    threats = [
        ThreatDetection(
            source=ThreatSource.CYBERARK_PTA,
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.CREDENTIAL_THEFT,
            description=f"Threat {i}"
        )
        for i in range(5)
    ]
    
    # Process threats
    for threat in threats:
        await response_engine.process_threat(threat)
    
    # Test listing with pagination
    threat_list, total = await response_engine.list_threats(page=1, page_size=3)
    assert len(threat_list) == 3
    assert total == 5
    
    # Test filtering by severity
    high_threats, high_total = await response_engine.list_threats(severity=ThreatSeverity.HIGH)
    assert high_total == 5
    
    # Test filtering by source
    cyberark_threats, cyberark_total = await response_engine.list_threats(source=ThreatSource.CYBERARK_PTA)
    assert cyberark_total == 5


@pytest.mark.asyncio
async def test_threat_acknowledgment(response_engine):
    """Test threat acknowledgment."""
    # Create a threat
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.MEDIUM,
        threat_type=ThreatType.SUSPICIOUS_ACTIVITY,
        description="Test threat"
    )
    
    threat_id = await response_engine.process_threat(threat)
    
    # Acknowledge the threat
    await response_engine.acknowledge_threat(threat_id)
    
    # Verify acknowledgment
    stored_threat = response_engine.threats[threat_id]
    assert stored_threat.acknowledged is True


@pytest.mark.asyncio
async def test_threat_escalation(response_engine):
    """Test threat escalation."""
    # Create a threat
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.LOW,
        threat_type=ThreatType.SUSPICIOUS_ACTIVITY,
        description="Test threat"
    )
    
    threat_id = await response_engine.process_threat(threat)
    
    # Escalate the threat
    await response_engine.escalate_threat(threat_id)
    
    # Verify escalation
    stored_threat = response_engine.threats[threat_id]
    assert stored_threat.escalated is True


@pytest.mark.asyncio
async def test_playbook_selection(response_engine):
    """Test playbook selection logic."""
    # Test credential theft trigger
    credential_threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.HIGH,
        threat_type=ThreatType.CREDENTIAL_THEFT,
        description="Credential theft"
    )
    
    playbook = response_engine._select_playbook(credential_threat)
    assert playbook is not None
    assert playbook.playbook_id == "credential_theft_response"
    
    # Test lateral movement trigger
    lateral_threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.HIGH,
        threat_type=ThreatType.LATERAL_MOVEMENT,
        description="Lateral movement"
    )
    
    playbook = response_engine._select_playbook(lateral_threat)
    assert playbook is not None
    assert playbook.playbook_id == "lateral_movement_response"
    
    # Test critical severity trigger
    critical_threat = ThreatDetection(
        source=ThreatSource.SPLUNK,
        severity=ThreatSeverity.CRITICAL,
        threat_type=ThreatType.MALWARE,
        description="Critical malware"
    )
    
    playbook = response_engine._select_playbook(critical_threat)
    assert playbook is not None
    assert playbook.playbook_id == "critical_threat_response"


@pytest.mark.asyncio
async def test_trigger_matching(response_engine):
    """Test trigger matching logic."""
    # Test exact match
    threat = ThreatDetection(
        source=ThreatSource.CYBERARK_PTA,
        severity=ThreatSeverity.HIGH,
        threat_type=ThreatType.CREDENTIAL_THEFT,
        description="Test"
    )
    
    trigger = {"threat_type": ThreatType.CREDENTIAL_THEFT, "severity": ThreatSeverity.HIGH}
    assert response_engine._matches_trigger(threat, trigger) is True
    
    # Test list match
    trigger = {"severity": [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]}
    assert response_engine._matches_trigger(threat, trigger) is True
    
    # Test no match
    trigger = {"threat_type": ThreatType.LATERAL_MOVEMENT}
    assert response_engine._matches_trigger(threat, trigger) is False


if __name__ == "__main__":
    pytest.main([__file__]) 