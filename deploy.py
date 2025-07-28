#!/usr/bin/env python3
"""
Deployment script for the Proactive Threat Mitigation PAM-SIEM system.

This script handles:
- Environment setup
- Dependency installation
- Configuration validation
- Service deployment
- Health checks
"""

import os
import sys
import subprocess
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List


class PAMSiemDeployer:
    """Deployment manager for the PAM-SIEM system."""
    
    def __init__(self, config_path: str = None):
        self.project_root = Path(__file__).parent
        self.config_path = config_path or self.project_root / "env.example"
        self.env_path = self.project_root / ".env"
        
    def run_command(self, command: List[str], cwd: Path = None) -> subprocess.CompletedProcess:
        """Run a shell command."""
        cwd = cwd or self.project_root
        print(f"Running: {' '.join(command)}")
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running command: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        
        print(f"Success: {result.stdout}")
        return result
    
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met."""
        print("Checking prerequisites...")
        
        # Check Python version
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
            print("Error: Python 3.8 or higher is required")
            return False
        
        print(f"✓ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        # Check if pip is available
        try:
            self.run_command([sys.executable, "-m", "pip", "--version"])
            print("✓ pip is available")
        except subprocess.CalledProcessError:
            print("Error: pip is not available")
            return False
        
        # Check if virtual environment is recommended
        if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            print("⚠️  Warning: Consider using a virtual environment")
        
        return True
    
    def setup_environment(self) -> bool:
        """Setup the environment configuration."""
        print("Setting up environment...")
        
        if not self.config_path.exists():
            print(f"Error: Configuration template not found at {self.config_path}")
            return False
        
        if not self.env_path.exists():
            print("Creating .env file from template...")
            try:
                # Copy template to .env
                with open(self.config_path, 'r') as f:
                    config_content = f.read()
                
                with open(self.env_path, 'w') as f:
                    f.write(config_content)
                
                print("✓ .env file created")
                print("⚠️  Please edit .env file with your actual configuration values")
                return True
            except Exception as e:
                print(f"Error creating .env file: {e}")
                return False
        else:
            print("✓ .env file already exists")
            return True
    
    def install_dependencies(self) -> bool:
        """Install Python dependencies."""
        print("Installing dependencies...")
        
        try:
            # Upgrade pip
            self.run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
            
            # Install dependencies
            self.run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            
            print("✓ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error installing dependencies: {e}")
            return False
    
    def validate_configuration(self) -> bool:
        """Validate the configuration."""
        print("Validating configuration...")
        
        if not self.env_path.exists():
            print("Error: .env file not found")
            return False
        
        # Load and validate configuration
        try:
            from app.core.config import settings
            
            # Check required settings
            required_settings = [
                'SECRET_KEY',
                'CYBERARK_PTA_URL',
                'CYBERARK_PTA_USERNAME',
                'CYBERARK_PTA_PASSWORD',
                'SPLUNK_HOST',
                'SPLUNK_USERNAME',
                'SPLUNK_PASSWORD',
                'TANIUM_SERVER',
                'TANIUM_USERNAME',
                'TANIUM_PASSWORD',
                'WEBHOOK_SECRET'
            ]
            
            missing_settings = []
            for setting in required_settings:
                if not getattr(settings, setting, None):
                    missing_settings.append(setting)
            
            if missing_settings:
                print(f"Error: Missing required configuration: {', '.join(missing_settings)}")
                return False
            
            print("✓ Configuration validated")
            return True
            
        except Exception as e:
            print(f"Error validating configuration: {e}")
            return False
    
    def run_tests(self) -> bool:
        """Run the test suite."""
        print("Running tests...")
        
        try:
            # Install test dependencies
            self.run_command([sys.executable, "-m", "pip", "install", "pytest", "pytest-asyncio"])
            
            # Run tests
            self.run_command([sys.executable, "-m", "pytest", "tests/", "-v"])
            
            print("✓ Tests passed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error running tests: {e}")
            return False
    
    def create_directories(self) -> bool:
        """Create necessary directories."""
        print("Creating directories...")
        
        directories = [
            "logs",
            "data",
            "config"
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(exist_ok=True)
            print(f"✓ Created directory: {directory}")
        
        return True
    
    def start_services(self) -> bool:
        """Start the application services."""
        print("Starting services...")
        
        try:
            # Start the main application
            self.run_command([sys.executable, "main.py"])
            
            print("✓ Services started successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error starting services: {e}")
            return False
    
    def health_check(self) -> bool:
        """Perform health checks."""
        print("Performing health checks...")
        
        try:
            import requests
            import time
            
            # Wait for service to start
            time.sleep(5)
            
            # Check health endpoint
            response = requests.get("http://localhost:8000/health", timeout=10)
            
            if response.status_code == 200:
                health_data = response.json()
                print(f"✓ Health check passed: {health_data}")
                return True
            else:
                print(f"Error: Health check failed with status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error performing health check: {e}")
            return False
    
    def deploy(self, skip_tests: bool = False, skip_health_check: bool = False) -> bool:
        """Perform the complete deployment."""
        print("Starting PAM-SIEM deployment...")
        print("=" * 50)
        
        steps = [
            ("Checking prerequisites", self.check_prerequisites),
            ("Setting up environment", self.setup_environment),
            ("Installing dependencies", self.install_dependencies),
            ("Validating configuration", self.validate_configuration),
            ("Creating directories", self.create_directories),
        ]
        
        if not skip_tests:
            steps.append(("Running tests", self.run_tests))
        
        steps.extend([
            ("Starting services", self.start_services),
        ])
        
        if not skip_health_check:
            steps.append(("Health check", self.health_check))
        
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            try:
                if not step_func():
                    print(f"❌ {step_name} failed")
                    return False
                print(f"✅ {step_name} completed")
            except Exception as e:
                print(f"❌ {step_name} failed with error: {e}")
                return False
        
        print("\n" + "=" * 50)
        print("🎉 PAM-SIEM deployment completed successfully!")
        print("\nNext steps:")
        print("1. Access the dashboard at: http://localhost:8000")
        print("2. View API documentation at: http://localhost:8000/docs")
        print("3. Monitor logs in the logs/ directory")
        print("4. Configure your CyberArk PTA, Splunk, and Tanium integrations")
        
        return True


def main():
    """Main deployment function."""
    parser = argparse.ArgumentParser(description="Deploy PAM-SIEM system")
    parser.add_argument("--config", help="Path to configuration template")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--skip-health-check", action="store_true", help="Skip health check")
    
    args = parser.parse_args()
    
    deployer = PAMSiemDeployer(args.config)
    
    try:
        success = deployer.deploy(
            skip_tests=args.skip_tests,
            skip_health_check=args.skip_health_check
        )
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nDeployment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Deployment failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 