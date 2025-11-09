#!/usr/bin/env python3
"""
ECH DNS Server
Uses HPKE encryption per RFC 9180 and draft-ietf-tls-esni
Teams get everything they need from DNS queries only

Claude Sonnet 4.5 used to generate code comments (human read and validated)
"""

from flask import Flask, request, jsonify, Response
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
import struct
import os

app = Flask(__name__)

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

# Load ECH private key (X25519 for HPKE)
with open('ech_private_key.pem', 'rb') as f:
    ech_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Load public key
with open('ech_public_key.pem', 'rb') as f:
    ech_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

FLAG = "CSAW{3NCrypt3D_CL13NT_H3LL0_RFC_C0MPL14NT_HPK3}"

def hpke_decrypt(encrypted_data, server_private_key):
    """
    Simplified HPKE decryption per RFC 9180
    
    encrypted_data format:
    - ephemeral_public_key (32 bytes)
    - ciphertext (variable)
    - tag (16 bytes)
    """
    try:
        if len(encrypted_data) < 48:  # 32 + 16 minimum
            return None, "Invalid encrypted data"
        
        # Extract ephemeral public key
        ephemeral_pk_bytes = encrypted_data[:32]
        ciphertext_and_tag = encrypted_data[32:]
        
        # Load ephemeral public key
        ephemeral_pk = x25519.X25519PublicKey.from_public_bytes(ephemeral_pk_bytes)
        
        # Perform ECDH to get shared secret
        shared_secret = server_private_key.exchange(ephemeral_pk)
        
        # Derive encryption key using HKDF (KDF in HPKE)
        # RFC 9180: HKDF-SHA256
        info = b"ECH v0xfe0d"  # Context string
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        key = kdf.derive(shared_secret)
        
        # Decrypt using ChaCha20-Poly1305 (AEAD in HPKE)
        cipher = ChaCha20Poly1305(key)
        nonce = b'\x00' * 12  # Simplified: single message, zero nonce
        
        plaintext = cipher.decrypt(nonce, ciphertext_and_tag, None)
        
        return plaintext, "OK"
        
    except Exception as e:
        return None, f"Decryption failed: {str(e)}"

def extract_inner_domain_from_ech(ech_header, server_private_key):
    """
    Extract inner domain from RFC-compliant ECH header
    Uses HPKE per RFC 9180
    """
    try:
        ech_data = base64.b64decode(ech_header)
        
        if len(ech_data) < 50:
            return None, "Invalid ECH"
        
        # Parse ECH structure
        version = struct.unpack('!H', ech_data[0:2])[0]
        if version != 0xfe0d:
            return None, "Invalid ECH version"
        
        # Remaining data is HPKE encrypted
        encrypted_payload = ech_data[2:]
        
        # Decrypt using HPKE
        plaintext, msg = hpke_decrypt(encrypted_payload, server_private_key)
        
        if plaintext is None:
            return None, msg
        
        # Parse decrypted payload: length + domain
        if len(plaintext) < 2:
            return None, "Invalid payload"
        
        domain_length = struct.unpack('!H', plaintext[0:2])[0]
        if len(plaintext) < 2 + domain_length:
            return None, "Invalid payload"
        
        inner_domain = plaintext[2:2+domain_length].decode('utf-8')
        
        return inner_domain, "OK"
        
    except Exception as e:
        return None, f"Invalid ECH: {str(e)}"

def create_dns_response(domain, record_type=1, ip_address=None, txt_data=None, https_record=None):
    """Create DNS response"""
    response = {
        "Status": 0 if (ip_address or https_record or record_type == 1) else 3,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": False,
        "Question": [{"name": domain, "type": record_type}],
        "Answer": []
    }
    
    if record_type == 1 and ip_address:
        response["Answer"].append({
            "name": domain,
            "type": 1,
            "TTL": 300,
            "data": ip_address
        })
        
        if txt_data:
            response["Answer"].append({
                "name": domain,
                "type": 16,
                "TTL": 300,
                "data": txt_data
            })
    
    if record_type == 65 and https_record:
        response["Answer"].append({
            "name": domain,
            "type": 65,
            "TTL": 300,
            "data": https_record
        })
    
    return response

def generate_echconfig():
    """
    Generate RFC-compliant ECHConfig per draft-ietf-tls-esni
    Contains ONLY public key - no secrets
    """
    # Get public key bytes (X25519)
    public_key_bytes = ech_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # RFC 9180 HPKE identifiers
    ech_config = {
        "version": 0xfe0d,
        "config_id": 1,
        "kem_id": 0x0020,      # DHKEM(X25519, HKDF-SHA256)
        "kdf_id": 0x0001,      # HKDF-SHA256
        "aead_id": 0x0003,     # ChaCha20Poly1305
        "public_name": "nyu.edu",
        "public_key": base64.b64encode(public_key_bytes).decode(),
        "maximum_name_length": 64
    }
    
    return json.dumps(ech_config)

@app.route('/dns-query', methods=['GET', 'POST'])
def dns_query():
    """RFC 8484 DNS over HTTPS endpoint"""
    
    if request.method == 'GET':
        outer_domain = request.args.get('name', 'unknown')
        try:
            query_type = int(request.args.get('type', '1'))
        except (ValueError, TypeError):
            query_type = 1
    else:
        outer_domain = request.args.get('name', 'unknown')
        try:
            query_type = int(request.args.get('type', '1'))
        except (ValueError, TypeError):
            query_type = 1
    
    ech_header = request.headers.get('X-ECH-Config')
    
    # RFC 9460: HTTPS record query (Type 65)
    if query_type == 65:
        if outer_domain == 'nyu.edu':
            echconfig = generate_echconfig()
            https_record_data = f"1 . ech={echconfig}"
            
            return jsonify(create_dns_response(
                'nyu.edu',
                record_type=65,
                https_record=https_record_data
            ))
        else:
            response = create_dns_response(outer_domain, record_type=65)
            return jsonify(response), 404
    
    # Standard A record queries
    if query_type == 1:
        # Normal query for nyu.edu
        if outer_domain == 'nyu.edu' and not ech_header:
            return jsonify(create_dns_response('nyu.edu', ip_address='10.0.1.1'))
        
        # ECH query to nyu.edu
        if outer_domain == 'nyu.edu' and ech_header:
            inner_domain, message = extract_inner_domain_from_ech(ech_header, ech_private_key)
            
            if inner_domain is None:
                response = create_dns_response('nyu.edu')
                response["Status"] = 5
                return jsonify(response), 403
            
            if inner_domain == 'csaw.io':
                return jsonify(create_dns_response(
                    'csaw.io',
                    ip_address='172.16.0.100',
                    txt_data=f"FLAG:{FLAG}"
                ))
            
            elif inner_domain == 'nyu.edu':
                return jsonify(create_dns_response('nyu.edu', ip_address='10.0.1.1'))
            
            else:
                response = create_dns_response(inner_domain)
                return jsonify(response), 404
        
        # Direct query for csaw.io
        if 'csaw.io' in outer_domain.lower():
            response = create_dns_response('csaw.io')
            response["Status"] = 5
            return jsonify(response), 403
    
    response = create_dns_response(outer_domain, record_type=query_type)
    return jsonify(response), 404

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/', methods=['GET'])
def index():
    html = """
    <html>
    <head>
        <title>DNS Server</title>
        <style>
            body { font-family: monospace; margin: 40px; background: #1e1e1e; color: #00ff00; }
            code { background: #000; padding: 2px 5px; }
        </style>
    </head>
    <body>
        <h1>DNS over HTTPS Server</h1>
        <p>RFC 8484 / RFC 9460 / RFC 9180 compliant</p>
        <p>Endpoint: <code>GET /dns-query?name=&lt;domain&gt;&amp;type=&lt;type&gt;</code></p>
        <p>Supported types: 1 (A), 65 (HTTPS)</p>
        <p>Public domain: <code>nyu.edu</code></p>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    print("RFC-Compliant ECH DNS Server")
    print("RFC 8484 (DoH) / RFC 9460 (HTTPS RR) / RFC 9180 (HPKE)")
    print(f"Port: 8053")
    app.run(host='0.0.0.0', port=8053, debug=False)
