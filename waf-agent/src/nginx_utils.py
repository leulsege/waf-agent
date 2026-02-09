"""
Nginx configuration utilities for WAF Agent
"""

import re
import subprocess
import shutil
import logging
from pathlib import Path
from .config import NGINX_SITES_AVAILABLE, NGINX_BINARY, SYSTEMCTL_BINARY, find_binary

logger = logging.getLogger(__name__)


def get_nginx_config_path(domain: str) -> Path:
    """Get the nginx config file path for a domain"""
    # Remove protocol and path if present
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.strip()
    
    logger.info(f"Looking for nginx config for domain: {domain}")
    logger.info(f"Searching in: {NGINX_SITES_AVAILABLE}")
    
    # Check if directory exists
    if not NGINX_SITES_AVAILABLE.exists():
        raise FileNotFoundError(f"Nginx sites-available directory not found: {NGINX_SITES_AVAILABLE}")
    
    # List available configs for debugging
    available_configs = list(NGINX_SITES_AVAILABLE.glob("*"))
    logger.info(f"Available config files: {[str(f.name) for f in available_configs if f.is_file()]}")
    
    # Check if file exists with domain name
    config_file = NGINX_SITES_AVAILABLE / domain
    
    if not config_file.exists():
        # Try common variations
        variations = [
            domain,
            f"{domain}.conf",
            domain.replace(".", "_"),
            f"{domain.replace('.', '_')}.conf",
        ]
        
        for var in variations:
            potential_file = NGINX_SITES_AVAILABLE / var
            logger.info(f"Trying: {potential_file}")
            if potential_file.exists():
                logger.info(f"Found config: {potential_file}")
                return potential_file
        
        # Show what files are available
        available = ", ".join([f.name for f in available_configs if f.is_file()])
        raise FileNotFoundError(
            f"Nginx config not found for domain: {domain}. "
            f"Available configs: {available}"
        )
    
    logger.info(f"Found config: {config_file}")
    return config_file


def read_nginx_config(config_path: Path) -> str:
    """Read nginx configuration file"""
    try:
        with open(config_path, 'r') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading nginx config: {e}")
        raise


def write_nginx_config(config_path: Path, content: str) -> None:
    """Write nginx configuration file"""
    try:
        # Create backup
        backup_path = config_path.with_suffix(f"{config_path.suffix}.backup")
        if config_path.exists():
            shutil.copy2(config_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
        
        # Write new config
        with open(config_path, 'w') as f:
            f.write(content)
        logger.info(f"Updated nginx config: {config_path}")
    except Exception as e:
        logger.error(f"Error writing nginx config: {e}")
        raise


def test_nginx_config() -> tuple[bool, str]:
    """Test nginx configuration"""
    try:
        result = subprocess.run(
            [NGINX_BINARY, '-t'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info("Nginx configuration test passed")
            return True, "Configuration test passed"
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Nginx configuration test failed: {error_msg}")
            return False, error_msg
    except FileNotFoundError:
        error_msg = f"Nginx binary not found at {NGINX_BINARY}. Please ensure nginx is installed."
        logger.error(error_msg)
        return False, error_msg
    except subprocess.TimeoutExpired:
        error_msg = "Nginx test command timed out"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error testing nginx config: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def reload_nginx() -> tuple[bool, str]:
    """Reload nginx configuration"""
    try:
        result = subprocess.run(
            [SYSTEMCTL_BINARY, 'reload', 'nginx'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info("Nginx reloaded successfully via systemctl")
            return True, "Nginx reloaded successfully"
        else:
            # Try alternative method
            service_binary = find_binary('service', ['/usr/sbin/service', '/sbin/service'])
            result = subprocess.run(
                [service_binary, 'nginx', 'reload'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info("Nginx reloaded successfully via service")
                return True, "Nginx reloaded successfully"
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Failed to reload nginx: {error_msg}")
            return False, error_msg
    except FileNotFoundError:
        error_msg = f"systemctl binary not found at {SYSTEMCTL_BINARY}. Please ensure systemd is installed."
        logger.error(error_msg)
        return False, error_msg
    except subprocess.TimeoutExpired:
        error_msg = "Nginx reload command timed out"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error reloading nginx: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def get_modsecurity_status(config_content: str) -> dict:
    """Get current ModSecurity status from nginx config content"""
    pattern = r'modsecurity\s+(on|off)\s*;'
    match = re.search(pattern, config_content, re.IGNORECASE)
    
    if match:
        status = match.group(1).lower()
        return {
            "modsecurity_enabled": status == "on",
            "status": status
        }
    else:
        return {
            "modsecurity_enabled": None,
            "status": "not_configured"
        }
