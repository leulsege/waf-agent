# Installation Guide - Ubuntu

## If you get "externally-managed-environment" error

Ubuntu 23.04+ requires virtual environments. Here's the quick fix:

### Option 1: Use Virtual Environment (Recommended)

```bash
cd /opt/waf-agent

# Install python3-venv if needed
sudo apt-get install -y python3-venv python3-pip

# Create virtual environment
sudo python3 -m venv venv

# Install dependencies
sudo venv/bin/pip install --upgrade pip
sudo venv/bin/pip install -r requirements.txt

# Generate keys
sudo venv/bin/python scripts/generate_keys.py

# Move keys to secure location
sudo mkdir -p /etc/waf-agent
sudo mv keys/private_key.pem /etc/waf-agent/
sudo mv keys/public_key.pem /etc/waf-agent/
sudo chmod 600 /etc/waf-agent/private_key.pem
sudo chmod 644 /etc/waf-agent/public_key.pem
```

### Option 2: Use the Installation Script

```bash
cd waf-agent
sudo bash scripts/install.sh
```

The script automatically handles virtual environment setup.

### Option 3: Manual Systemd Service (if using venv)

Update `/etc/systemd/system/waf-agent.service`:

```ini
[Service]
ExecStart=/opt/waf-agent/venv/bin/python -m src.main
```

### Testing

```bash
# Run manually to test
cd /opt/waf-agent
sudo venv/bin/python -m src.main

# Or use the service
sudo systemctl start waf-agent
sudo systemctl status waf-agent
```

## Why Virtual Environment?

- ✅ Prevents breaking system Python packages
- ✅ Isolated dependencies
- ✅ Follows Ubuntu/PEP 668 best practices
- ✅ Safe for production
