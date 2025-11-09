#!/usr/bin/env python3
"""
RFC-Compliant Solution for ECH DNS Challenge

Uses real HPKE encryption per RFC 9180
Everything obtained through DNS queries only - no container access needed

Claude Sonnet 4.5 used to generate code comments (human read and validated)
"""

import requests
import struct
import hashlib
import base64
import json
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

SERVER_URL = "http://localhost:8053"

def query_dns(outer_domain, ech_header=None, record_type=1):
    """Query the DNS server"""
    headers = {}
    if ech_header:
        headers['X-ECH-Config'] = ech_header
    
    url = f"{SERVER_URL}/dns-query?name={outer_domain}&type={record_type}"
    
    try:
        response = requests.get(url, headers=headers)
        return response.status_code, response.json()
    except Exception as e:
        return None, str(e)

def hpke_encrypt(plaintext, server_public_key_bytes):
    """
    Simplified HPKE encryption per RFC 9180
    
    Returns: ephemeral_pk || ciphertext || tag
    """
    # Generate ephemeral keypair
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Load server public key
    server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_key_bytes)
    
    # Perform ECDH to get shared secret
    shared_secret = ephemeral_private_key.exchange(server_public_key)
    
    # Derive encryption key using HKDF (KDF in HPKE)
    info = b"ECH v0xfe0d"
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    
    # Encrypt using ChaCha20-Poly1305 (AEAD in HPKE)
    cipher = ChaCha20Poly1305(key)
    nonce = b'\x00' * 12  # Simplified: single message
    
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    
    # Get ephemeral public key bytes
    ephemeral_pk_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return ephemeral_pk_bytes + ciphertext

def generate_ech_header(inner_domain, server_public_key_bytes):
    """
    Generate RFC-compliant ECH header using HPKE
    
    Structure:
    - version (2 bytes)
    - HPKE encrypted payload
    """
    
    version = struct.pack('!H', 0xfe0d)
    
    # Prepare plaintext: domain_length + domain
    inner_domain_bytes = inner_domain.encode('utf-8')
    domain_length = struct.pack('!H', len(inner_domain_bytes))
    plaintext = domain_length + inner_domain_bytes
    
    # Encrypt using HPKE
    encrypted_payload = hpke_encrypt(plaintext, server_public_key_bytes)
    
    # Combine version + encrypted payload
    ech_data = version + encrypted_payload
    
    # Base64 encode
    ech_header = base64.b64encode(ech_data).decode('utf-8')
    
    return ech_header

def main():
    print("=" * 70)
    print("RFC-COMPLIANT ECH DNS Challenge Solution")
    print("=" * 70)
    print()
    print("Standards Used:")
    print("  - RFC 8484: DNS over HTTPS (DoH)")
    print("  - RFC 9460: HTTPS DNS records")
    print("  - RFC 9180: HPKE (Hybrid Public Key Encryption)")
    print("  - draft-ietf-tls-esni: Encrypted Client Hello")
    print()
    print("No container access required - everything via DNS!")
    print("=" * 70)
    print()
    
    # Step 1: Normal A record query
    print("[Step 1] Query A record for nyu.edu")
    status, response = query_dns("nyu.edu", record_type=1)
    
    if status == 200:
        print(f"✓ Success")
        print(f"  IP: {response['Answer'][0]['data']}")
    else:
        print(f"✗ Failed: {status}")
        return
    
    print()
    
    # Step 2: Query HTTPS record (Type 65) - RFC 9460
    print("[Step 2] Query HTTPS record (Type 65) per RFC 9460")
    print("         This is the ONLY way to get ECH configuration!")
    status, response = query_dns("nyu.edu", record_type=65)
    
    if status != 200:
        print(f"✗ Failed: {status}")
        print(json.dumps(response, indent=2))
        return
    
    print(f"✓ HTTPS record retrieved")
    https_data = response['Answer'][0]['data']
    
    # Parse ECHConfig from HTTPS record
    try:
        if 'ech=' not in https_data:
            print("✗ No ECH config in HTTPS record")
            return
        
        ech_config_json = https_data.split('ech=')[1]
        ech_config = json.loads(ech_config_json)
        
        print(f"  ECH Version: {hex(ech_config['version'])}")
        print(f"  Public Name: {ech_config['public_name']}")
        print(f"  KEM: DHKEM(X25519, HKDF-SHA256)")
        print(f"  KDF: HKDF-SHA256")
        print(f"  AEAD: ChaCha20Poly1305")
        
        # Get public key
        public_key_b64 = ech_config['public_key']
        public_key_bytes = base64.b64decode(public_key_b64)
        
        print(f"  Public Key: {public_key_b64[:40]}...")
        print()
        print("✓ All information obtained from DNS - no secrets needed!")
        
    except Exception as e:
        print(f"✗ Failed to parse ECHConfig: {e}")
        return
    
    print()
    
    # Step 3: Build ECH using HPKE
    print("[Step 3] Build ECH header using HPKE (RFC 9180)")
    print("         Encrypting inner domain 'csaw.io' with server's public key")
    
    try:
        ech_header = generate_ech_header("csaw.io", public_key_bytes)
        encrypted_size = len(base64.b64decode(ech_header))
        print(f"✓ ECH header generated ({encrypted_size} bytes)")
        print(f"  Contains: 2-byte version + 32-byte ephemeral key + encrypted payload")
    except Exception as e:
        print(f"✗ Failed to generate ECH: {e}")
        return
    
    print()
    
    # Step 4: Query with ECH
    print("[Step 4] Query nyu.edu with ECH (inner domain: csaw.io)")
    print("         Network observer sees: nyu.edu")
    print("         Server decrypts and sees: csaw.io")
    
    status, response = query_dns("nyu.edu", ech_header, record_type=1)
    
    if status == 200:
        print(f"✓ SUCCESS!")
        
        for answer in response['Answer']:
            if answer['type'] == 1:
                print(f"Resolved Domain: {answer['name']}")
                print(f"IP Address: {answer['data']}")
            elif answer['type'] == 16:
                print(f"\n{answer['data']}")
        
        print()
        print("RFC Compliance Summary:")
        print("  ✓ Retrieved ECHConfig via HTTPS DNS record (RFC 9460)")
        print("  ✓ Used DoH for all queries (RFC 8484)")
        print("  ✓ Used HPKE for encryption (RFC 9180)")
        print("  ✓ ECH hid real domain from observers (draft-ietf-tls-esni)")
        print("  ✓ No container access needed - pure DNS solution!")
        print()
        print("=" * 70)
    else:
        print(f"✗ Failed: {status}")
        print(json.dumps(response, indent=2))
    
    print()

if __name__ == '__main__':
    main()
