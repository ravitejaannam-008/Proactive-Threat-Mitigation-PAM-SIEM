#!/usr/bin/env python3
"""
Proactive Threat Mitigation via Integrated PAM & SIEM
Main Application Entry Point

This application integrates CyberArk PTA, Splunk, and Tanium to create
an automated "detect and respond" playbook for credential theft and lateral movement.
"""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.v1.api import api_router
from app.core.middleware import RequestLoggingMiddleware
from app.core.monitoring import setup_monitoring
from app.services.response_engine import ResponseEngine
from app.services.cyberark_integration import CyberArkPTA
from app.services.splunk_integration import SplunkIntegration
from app.services.tanium_integration import TaniumIntegration

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Global service instances
response_engine = None
cyberark_pta = None
splunk_integration = None
tanium_integration = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    global response_engine, cyberark_pta, splunk_integration, tanium_integration
    
    logger.info("Starting Proactive Threat Mitigation PAM-SIEM System...")
    
    try:
        # Initialize core services
        logger.info("Initializing CyberArk PTA integration...")
        cyberark_pta = CyberArkPTA()
        await cyberark_pta.initialize()
        
        logger.info("Initializing Splunk integration...")
        splunk_integration = SplunkIntegration()
        await splunk_integration.initialize()
        
        logger.info("Initializing Tanium integration...")
        tanium_integration = TaniumIntegration()
        await tanium_integration.initialize()
        
        logger.info("Initializing Response Engine...")
        response_engine = ResponseEngine(
            cyberark_pta=cyberark_pta,
            splunk_integration=splunk_integration,
            tanium_integration=tanium_integration
        )
        await response_engine.initialize()
        
        logger.info("Starting background tasks...")
        asyncio.create_task(response_engine.start_monitoring())
        
        logger.info("✅ Proactive Threat Mitigation System started successfully!")
        logger.info(f"📊 Dashboard available at: http://{settings.HOST}:{settings.PORT}")
        logger.info(f"📚 API Documentation at: http://{settings.HOST}:{settings.PORT}/docs")
        
    except Exception as e:
        logger.error(f"❌ Failed to start system: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Proactive Threat Mitigation System...")
    
    try:
        if response_engine:
            await response_engine.shutdown()
        if cyberark_pta:
            await cyberark_pta.shutdown()
        if splunk_integration:
            await splunk_integration.shutdown()
        if tanium_integration:
            await tanium_integration.shutdown()
        
        logger.info("✅ System shutdown completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error during shutdown: {e}")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="""
        Proactive Threat Mitigation via Integrated PAM & SIEM
        
        This system integrates CyberArk PTA, Splunk, and Tanium to create
        an automated "detect and respond" playbook for credential theft and lateral movement.
        
        ## Key Features
        
        - **Real-time Threat Detection**: CyberArk PTA identifies high-risk anomalous behaviors
        - **Unified Dashboard**: Splunk provides real-time visualization of privileged threats
        - **Automated Response**: Session isolation and credential rotation upon threat detection
        - **Cross-Platform Integration**: Seamless communication between PAM, SIEM, and endpoint management
        - **Performance Metrics**: MTTR reduction from 4+ hours to under 3 minutes
        
        ## Architecture
        
        The system creates a proactive defense mechanism that moves from reactive to predictive security,
        automatically containing threats before they can escalate.
        """,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )
    
    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_HOSTS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )
    
    app.add_middleware(RequestLoggingMiddleware)
    
    # Add Prometheus metrics endpoint
    if settings.METRICS_ENABLED:
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "message": "An unexpected error occurred",
                "request_id": getattr(request.state, "request_id", "unknown")
            }
        )
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint for monitoring."""
        return {
            "status": "healthy",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT
        }
    
    # Root endpoint
    @app.get("/")
    async def root():
        """Root endpoint with system information."""
        return {
            "message": "Proactive Threat Mitigation PAM-SIEM System",
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs",
            "health": "/health",
            "metrics": "/metrics" if settings.METRICS_ENABLED else None
        }
    
    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        workers=settings.WORKERS if not settings.DEBUG else 1,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    ) 