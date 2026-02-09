# WAF Agent

Python-based agent that manages ModSecurity on/off status for nginx domains. Handles encrypted communication and nginx configuration updates.

## Features

- ✅ Encrypted communication using RSA public/private key pairs
- ✅ Updates nginx configuration files automatically
- ✅ Tests nginx config before applying changes
- ✅ Creates backups before modifications
- ✅ Reloads nginx after successful updates
- ✅ RESTful API with FastAPI
- ✅ Health check endpoint
- ✅ Status query endpoint

## Project Structure

```
waf-agent/
├── src/                    # Source code
│   ├── __init__.py
│   ├── main.py            # FastAPI application
│   ├── config.py          # Configuration constants
│   ├── security.py        # Authentication & signature verification
│   ├── nginx_utils.py     # Nginx configuration utilities
│   └── waf_toggle.py      # WAF toggle functionality
├── scripts/               # Utility scripts
│   ├── generate_keys.py   # RSA key pair generator
│   ├── install.sh         # Installation script
│   └── test_toggle.sh      # Testing script
├── systemd/               # Systemd service files
│   └── waf-agent.service  # Service configuration
├── docs/                  # Documentation
│   └── INSTALLATION.md    # Installation guide
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Quick Start

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for detailed installation instructions.

### Quick Install

```bash
sudo bash scripts/install.sh
```

## Requirements

- Python 3.8+
- nginx installed and configured
- Root/sudo access (for nginx operations)
- RSA key pair for encryption

## API Endpoints

### Health Check
```bash
GET /health
```

### Toggle WAF Status
```bash
POST /waf/toggle
Content-Type: application/json
Authorization: Bearer <token>

{
  "domain": "example.com",
  "enabled": true,
  "signature": "<base64_encoded_signature>"
}
```

### Get WAF Status
```bash
GET /waf/status/{domain}
```

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the agent
python -m src.main
```

## License

Internal use only.
