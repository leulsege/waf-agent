"""
Configuration constants and utilities for WAF Agent
"""

import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Configuration paths
NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")
PRIVATE_KEY_PATH = Path(os.getenv("WAF_AGENT_PRIVATE_KEY", "/etc/waf-agent/private_key.pem"))
PUBLIC_KEY_PATH = Path(os.getenv("WAF_AGENT_PUBLIC_KEY", "/etc/waf-agent/public_key.pem"))

# WAF IP blocking paths
WAF_BLOCKS_DIR = Path("/etc/nginx/waf/blocks")
WAF_MAPS_DIR = Path("/etc/nginx/waf/maps")
WAF_SERVERS_DIR = Path("/etc/nginx/waf/servers")

# Find nginx and systemctl binaries
def find_binary(name: str, common_paths: list[str] = None) -> str:
    """Find a binary in common system paths"""
    if common_paths is None:
        common_paths = [
            f"/usr/sbin/{name}",
            f"/usr/bin/{name}",
            f"/sbin/{name}",
            f"/bin/{name}",
            name  # Try in PATH as fallback
        ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Last resort: try which/whereis
    try:
        result = subprocess.run(['which', name], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    
    # Return the name itself if not found (will fail with better error message)
    return name

NGINX_BINARY = find_binary('nginx', ['/usr/sbin/nginx', '/usr/bin/nginx', '/sbin/nginx'])
SYSTEMCTL_BINARY = find_binary('systemctl', ['/usr/bin/systemctl', '/bin/systemctl'])

# Log found binaries at startup
logger.info(f"Using nginx binary: {NGINX_BINARY}")
logger.info(f"Using systemctl binary: {SYSTEMCTL_BINARY}")
