"""
Configuration management for the PAM-SIEM integration system.
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Application Configuration
    APP_NAME: str = Field(default="Proactive-Threat-Mitigation-PAM-SIEM", env="APP_NAME")
    APP_VERSION: str = Field(default="1.0.0", env="APP_VERSION")
    DEBUG: bool = Field(default=False, env="DEBUG")
    ENVIRONMENT: str = Field(default="production", env="ENVIRONMENT")
    
    # Server Configuration
    HOST: str = Field(default="0.0.0.0", env="HOST")
    PORT: int = Field(default=8000, env="PORT")
    WORKERS: int = Field(default=4, env="WORKERS")
    
    # Security
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ALGORITHM: str = Field(default="HS256", env="ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # CORS and Hosts
    ALLOWED_HOSTS: List[str] = Field(default=["*"], env="ALLOWED_HOSTS")
    
    @validator("ALLOWED_HOSTS", pre=True)
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    # Database Configuration
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    DATABASE_POOL_SIZE: int = Field(default=20, env="DATABASE_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(default=30, env="DATABASE_MAX_OVERFLOW")
    
    # Redis Configuration
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    
    # CyberArk PTA Configuration
    CYBERARK_PTA_URL: str = Field(..., env="CYBERARK_PTA_URL")
    CYBERARK_PTA_USERNAME: str = Field(..., env="CYBERARK_PTA_USERNAME")
    CYBERARK_PTA_PASSWORD: str = Field(..., env="CYBERARK_PTA_PASSWORD")
    CYBERARK_PTA_VERIFY_SSL: bool = Field(default=True, env="CYBERARK_PTA_VERIFY_SSL")
    CYBERARK_PTA_TIMEOUT: int = Field(default=30, env="CYBERARK_PTA_TIMEOUT")
    
    # Splunk Configuration
    SPLUNK_HOST: str = Field(..., env="SPLUNK_HOST")
    SPLUNK_PORT: int = Field(default=8089, env="SPLUNK_PORT")
    SPLUNK_USERNAME: str = Field(..., env="SPLUNK_USERNAME")
    SPLUNK_PASSWORD: str = Field(..., env="SPLUNK_PASSWORD")
    SPLUNK_INDEX: str = Field(default="threat_alerts", env="SPLUNK_INDEX")
    SPLUNK_VERIFY_SSL: bool = Field(default=True, env="SPLUNK_VERIFY_SSL")
    
    # Tanium Configuration
    TANIUM_SERVER: str = Field(..., env="TANIUM_SERVER")
    TANIUM_USERNAME: str = Field(..., env="TANIUM_USERNAME")
    TANIUM_PASSWORD: str = Field(..., env="TANIUM_PASSWORD")
    TANIUM_VERIFY_SSL: bool = Field(default=True, env="TANIUM_VERIFY_SSL")
    TANIUM_TIMEOUT: int = Field(default=60, env="TANIUM_TIMEOUT")
    
    # Webhook Configuration
    WEBHOOK_SECRET: str = Field(..., env="WEBHOOK_SECRET")
    WEBHOOK_TIMEOUT: int = Field(default=10, env="WEBHOOK_TIMEOUT")
    
    # Monitoring Configuration
    PROMETHEUS_PORT: int = Field(default=9090, env="PROMETHEUS_PORT")
    METRICS_ENABLED: bool = Field(default=True, env="METRICS_ENABLED")
    HEALTH_CHECK_INTERVAL: int = Field(default=30, env="HEALTH_CHECK_INTERVAL")
    
    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(default="json", env="LOG_FORMAT")
    LOG_FILE: str = Field(default="logs/app.log", env="LOG_FILE")
    
    # Alert Configuration
    ALERT_EMAIL_SMTP_SERVER: str = Field(default="smtp.gmail.com", env="ALERT_EMAIL_SMTP_SERVER")
    ALERT_EMAIL_PORT: int = Field(default=587, env="ALERT_EMAIL_PORT")
    ALERT_EMAIL_USERNAME: str = Field(default="", env="ALERT_EMAIL_USERNAME")
    ALERT_EMAIL_PASSWORD: str = Field(default="", env="ALERT_EMAIL_PASSWORD")
    ALERT_EMAIL_FROM: str = Field(default="", env="ALERT_EMAIL_FROM")
    ALERT_EMAIL_TO: str = Field(default="", env="ALERT_EMAIL_TO")
    
    # Response Engine Configuration
    AUTO_RESPONSE_ENABLED: bool = Field(default=True, env="AUTO_RESPONSE_ENABLED")
    CREDENTIAL_ROTATION_ENABLED: bool = Field(default=True, env="CREDENTIAL_ROTATION_ENABLED")
    SESSION_ISOLATION_ENABLED: bool = Field(default=True, env="SESSION_ISOLATION_ENABLED")
    RESPONSE_TIMEOUT: int = Field(default=300, env="RESPONSE_TIMEOUT")
    
    # Performance Configuration
    MAX_CONCURRENT_RESPONSES: int = Field(default=10, env="MAX_CONCURRENT_RESPONSES")
    RESPONSE_QUEUE_SIZE: int = Field(default=100, env="RESPONSE_QUEUE_SIZE")
    CACHE_TTL: int = Field(default=3600, env="CACHE_TTL")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Create global settings instance
settings = Settings() 