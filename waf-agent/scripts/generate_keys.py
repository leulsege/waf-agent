#!/usr/bin/env python3
"""
Generate RSA key pair for WAF Agent encryption
Run this script to generate public/private key pair
"""

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def generate_key_pair():
    """Generate RSA key pair"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


def save_keys(private_pem: bytes, public_pem: bytes, output_dir: Path = Path("keys")):
    """Save keys to files"""
    output_dir.mkdir(exist_ok=True)
    
    private_key_path = output_dir / "private_key.pem"
    public_key_path = output_dir / "public_key.pem"
    
    # Set secure permissions for private key
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    os.chmod(private_key_path, 0o600)  # Read/write for owner only
    
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)
    os.chmod(public_key_path, 0o644)  # Readable by all
    
    print(f"✅ Keys generated successfully!")
    print(f"   Private key: {private_key_path}")
    print(f"   Public key: {public_key_path}")
    print(f"\n⚠️  IMPORTANT:")
    print(f"   - Keep the private key SECRET and secure")
    print(f"   - Share the public key with the backend service")
    print(f"   - Private key should be on the agent server only")
    
    return private_key_path, public_key_path


if __name__ == "__main__":
    print("Generating RSA key pair for WAF Agent...")
    private_pem, public_pem = generate_key_pair()
    save_keys(private_pem, public_pem)

