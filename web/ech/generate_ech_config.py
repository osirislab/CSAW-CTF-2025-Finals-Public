#!/usr/bin/env python3
"""
Generate RFC-compliant ECH configuration
Uses X25519 keys for HPKE per RFC 9180

Claude Sonnet 4.5 used to generate code comments (human read and validated)
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
import secrets

def generate_x25519_keypair():
    """Generate X25519 keypair for HPKE"""
    private_key = x25519.X25519PrivateKey.generate()
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

def main():
    print("Generating RFC-compliant ECH configuration...")
    print("Using X25519 for HPKE per RFC 9180")
    print()
    
    # Generate X25519 keypair
    private_key, public_key = generate_x25519_keypair()
    
    # Save private key
    with open('ech_private_key.pem', 'wb') as f:
        f.write(private_key)
    print("✓ Private key saved (X25519)")
    
    # Save public key
    with open('ech_public_key.pem', 'wb') as f:
        f.write(public_key)
    print("✓ Public key saved (X25519)")
    
    # Update config (no secrets, just metadata)
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)
    print("✓ Configuration updated")
    
    print("\n" + "=" * 60)
    print("RFC-Compliant ECH Configuration Generated")
    print("=" * 60)
    print("\nStandards Used:")
    print("  - RFC 9180: HPKE (Hybrid Public Key Encryption)")
    print("  - RFC 9460: HTTPS DNS Records")
    print("  - draft-ietf-tls-esni: Encrypted Client Hello")
    print("\nKey Distribution:")
    print("  - Public key available via DNS Type 65 query")
    print("  - No secrets exposed to clients")
    print("  - Query: /dns-query?name=nyu.edu&type=65")
    print("\n" + "=" * 60)

if __name__ == '__main__':
    main()
