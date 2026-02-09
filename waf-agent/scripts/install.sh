#!/bin/bash
# WAF Agent Installation Script for Ubuntu
# Run with: sudo bash install.sh

set -e  # Exit on error

echo "=========================================="
echo "WAF Agent Installation Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL_DIR="/opt/waf-agent"
KEYS_DIR="/etc/waf-agent"

echo -e "${GREEN}Step 1: Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$KEYS_DIR"
chmod 700 "$KEYS_DIR"
chown root:root "$KEYS_DIR"

echo -e "${GREEN}Step 2: Copying files...${NC}"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cp -r "$PROJECT_ROOT/src" "$INSTALL_DIR/"
cp "$PROJECT_ROOT/requirements.txt" "$INSTALL_DIR/"
cp "$PROJECT_ROOT/README.md" "$INSTALL_DIR/" 2>/dev/null || true

# Make Python files executable
chmod +x "$INSTALL_DIR/src/main.py"

# Set ownership
chown -R root:root "$INSTALL_DIR"

echo -e "${GREEN}Step 3: Creating Python virtual environment...${NC}"
cd "$INSTALL_DIR"

# Check if python3-venv is installed
if ! python3 -m venv --help &> /dev/null; then
    echo -e "${YELLOW}python3-venv not found. Installing...${NC}"
    apt-get update
    apt-get install -y python3-venv python3-pip
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
else
    echo -e "${YELLOW}Virtual environment already exists${NC}"
fi

echo -e "${GREEN}Step 4: Installing Python dependencies...${NC}"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo -e "${GREEN}Step 5: Generating RSA key pair...${NC}"
cd "$INSTALL_DIR"
if [ ! -f "$KEYS_DIR/private_key.pem" ]; then
    "$INSTALL_DIR/venv/bin/python" "$SCRIPT_DIR/generate_keys.py"
    
    # Move keys to secure location
    if [ -f "keys/private_key.pem" ]; then
        mv keys/private_key.pem "$KEYS_DIR/"
        mv keys/public_key.pem "$KEYS_DIR/"
        chmod 600 "$KEYS_DIR/private_key.pem"
        chmod 644 "$KEYS_DIR/public_key.pem"
        chown root:root "$KEYS_DIR"/*
        rm -rf keys
        echo -e "${GREEN}Keys generated and secured!${NC}"
    else
        echo -e "${RED}Key generation failed!${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Keys already exist, skipping generation${NC}"
fi

echo -e "${GREEN}Step 6: Creating systemd service...${NC}"
cat > /etc/systemd/system/waf-agent.service << EOF
[Unit]
Description=WAF Agent Service
After=network.target nginx.service
Requires=nginx.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=/usr/bin:/usr/local/bin"
Environment="WAF_AGENT_PRIVATE_KEY=$KEYS_DIR/private_key.pem"
Environment="WAF_AGENT_PUBLIC_KEY=$KEYS_DIR/public_key.pem"
ExecStart=$INSTALL_DIR/venv/bin/python -m src.main
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Step 7: Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable waf-agent
systemctl start waf-agent

echo ""
echo -e "${GREEN}=========================================="
echo "Installation Complete!"
echo "==========================================${NC}"
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "Keys directory: $KEYS_DIR"
echo ""
echo "Service commands:"
echo "  sudo systemctl status waf-agent  # Check status"
echo "  sudo systemctl restart waf-agent # Restart service"
echo "  sudo journalctl -u waf-agent -f  # View logs"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  - Private key: $KEYS_DIR/private_key.pem (KEEP SECRET!)"
echo "  - Public key: $KEYS_DIR/public_key.pem (share with backend)"
echo ""
echo -e "${GREEN}Testing agent...${NC}"
sleep 2
if curl -s http://localhost:8080/health > /dev/null; then
    echo -e "${GREEN}✅ Agent is running!${NC}"
    curl -s http://localhost:8080/health | python3 -m json.tool
else
    echo -e "${YELLOW}⚠️  Agent may not be running yet. Check status:${NC}"
    echo "  sudo systemctl status waf-agent"
fi

