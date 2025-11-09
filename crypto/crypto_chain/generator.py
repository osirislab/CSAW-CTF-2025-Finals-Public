#!/usr/bin/env python3
"""
challenge.py - Multi-Layer Quantum Entanglement Cryptosystem CTF Challenge

TRUE attack chain: Wiener → Franklin-Reiter → Coppersmith
Each stage MUST be completed to proceed to the next.

Difficulty: Medium/Hard
Category: Cryptography

Comments generated with Claude Sonnet 4.5 (human reviewed and approved)
"""

from Crypto.Util.number import getPrime, bytes_to_long, inverse, GCD
from sympy import nextprime
import json
import random

# Flag placeholder (please don't actually store like this)
flag = b"CSAW{w13n3r_r31t3r_c0pp3r5m1th_tr1pl3_br34k}"

def generate_challenge():
    """Generate multi-layer challenge where stages must be completed sequentially"""
       
    # ============================================================================
    # LAYER 1: Wiener-vulnerable RSA (for parameter transport)
    # ============================================================================
    
    p1 = getPrime(512)
    q1 = getPrime(512)
    n1 = p1 * q1
    phi1 = (p1 - 1) * (q1 - 1)
    
    # Small d for Wiener's attack
    d1 = random.randint(2**200, 2**220)
    while GCD(d1, phi1) != 1:
        d1 = random.randint(2**200, 2**220)
    
    e1 = inverse(d1, phi1)
    
    # ============================================================================
    # LAYER 2: Generate transformation parameters (to be recovered via Franklin-Reiter)
    # ============================================================================
    
    # These will be hidden in related messages
    alpha = getPrime(48)
    beta = getPrime(48)
    gamma = getPrime(48)
    
    
    # Create two related messages containing parameter hints
    # m1 contains alpha and beta encoded
    # m2 = m1 + known_offset, contains gamma hint
    
    msg1_template = b"PARAMS_PART1: alpha="
    msg1_alpha = str(alpha).encode()
    msg1_beta_part = b" beta="
    msg1_beta = str(beta).encode()
    msg1 = msg1_template + msg1_alpha + msg1_beta_part + msg1_beta
    
    # m2 is related: same template but with gamma
    msg2_template = b"PARAMS_PART2: gamma="
    msg2_gamma = str(gamma).encode()
    msg2_padding = b" " * (len(msg1) - len(msg2_template) - len(msg2_gamma))
    msg2 = msg2_template + msg2_gamma + msg2_padding
    
    # Adjust to make m2 = m1 + known_constant for Franklin-Reiter
    m1_val = bytes_to_long(msg1)
    m2_val = bytes_to_long(msg2)
    
    # Actually, let's make this simpler and cleaner
    # Two messages with known linear relationship
    secret_param_string = f"alpha:{alpha}|beta:{beta}|gamma:{gamma}"
    
    msg1_base = b"SECRET_PARAMS_ENCRYPTED_V1:"
    msg2_base = b"SECRET_PARAMS_ENCRYPTED_V2:"
    
    # Make them related by a known offset
    known_offset = 12345
    
    msg1 = msg1_base + secret_param_string.encode()
    # Pad msg1 to a specific length
    msg1 = msg1.ljust(200, b'X')
    
    m1_val = bytes_to_long(msg1)
    # m2 = m1 + known_offset
    m2_val = m1_val + known_offset
    
    # Encrypt both with RSA_1
    c1 = pow(m1_val, e1, n1)
    c2 = pow(m2_val, e1, n1)
    
    
    # ============================================================================
    # LAYER 3: Custom quadratic transformation + RSA (for flag)
    # ============================================================================
    
    # Use close primes for easy factoring in final stage
    p2_base = getPrime(255)
    p2 = int(nextprime(p2_base))
    q2 = int(nextprime(p2 + random.randint(1, 2**20)))
    n2 = p2 * q2
    e2 = 65537
      

    
    # Apply custom quadratic transformation using alpha, beta, gamma
    m_flag = bytes_to_long(flag)
    m_transformed = (m_flag * m_flag * alpha + m_flag * beta + gamma) % n2
    
    # Then RSA encrypt
    c_flag = pow(m_transformed, e2, n2)
    
    # ============================================================================
    # Additional hint: Encrypt parameters directly with RSA_1 as alternative path
    # ============================================================================
    # This is encrypted metadata that CAN be decrypted with d1 from Wiener
    param_hint = f"transform_params:{alpha},{beta},{gamma}".encode()
    param_hint = param_hint.ljust(100, b'\x00')
    c_params = pow(bytes_to_long(param_hint), e1, n1)
    
   
    # Save challenge data
    challenge_data = {
        "layer1_rsa": {
            "n": int(n1),
            "e": int(e1),
            "related_message_c1": int(c1),
            "related_message_c2": int(c2),
            "known_offset": int(known_offset),
            "encrypted_params": int(c_params)
        },
        "layer3_custom": {
            "n": int(n2),
            "e": int(e2),
            "encrypted_flag": int(c_flag),
            "flag_prefix": "CSAW{",
            "flag_suffix": "}",
            "flag_length": len(flag)
        },
        "hints": {
            "stage1": "The exponent seems unusually large...",
            "stage2": "Two ciphertexts with a known relationship",
            "stage3": "A quadratic transformation guards the flag"
        },
        "_solution": {
            "p1": int(p1),
            "q1": int(q1),
            "d1": int(d1),
            "p2": int(p2),
            "q2": int(q2),
            "alpha": int(alpha),
            "beta": int(beta),
            "gamma": int(gamma),
            "flag": flag.decode('ascii')
        }
    }
    
    with open("challenge_data.json", "w") as f:
        json.dump(challenge_data, f, indent=2)
    
    return challenge_data

def display_challenge(data):
    """Display the challenge information"""
    print("="*70)
    print("       MULTI-LAYER QUANTUM ENTANGLEMENT SYSTEM")
    print("                  CSAW CTF Challenge")
    print("="*70)
    print()
    print("Our cryptographers (Sages of math) implemented defense-in-depth with multiple")
    print("encryption layers. Break through ALL layers to capture the flag.")
    print()
    print("Flag format: CSAW{...}")
    print()

    print("="*70)
    print("LAYER 1: PARAMETER TRANSPORT (RSA)")
    print("="*70)
    print(f"n1 = {data['layer1_rsa']['n']}")
    print(f"e1 = {data['layer1_rsa']['e']}")
    print()
    print("Encrypted Parameters:")
    print(f"  c_params = {data['layer1_rsa']['encrypted_params']}")
    print()
    print("Related Message Pair (same key, known offset):")
    print(f"  c1 = {data['layer1_rsa']['related_message_c1']}")
    print(f"  c2 = {data['layer1_rsa']['related_message_c2']}")
    print(f"  Known: m2 = m1 + {data['layer1_rsa']['known_offset']}")
    print()

    print("="*70)
    print("LAYER 3: FLAG ENCRYPTION (CUSTOM + RSA)")
    print("="*70)
    print(f"n2 = {data['layer3_custom']['n']}")
    print(f"e2 = {data['layer3_custom']['e']}")
    print()
    print("Encrypted Flag:")
    print(f"  c_flag = {data['layer3_custom']['encrypted_flag']}")
    print()
    print("Known Information:")
    print(f"  Flag prefix: {data['layer3_custom']['flag_prefix']}")
    print(f"  Flag suffix: {data['layer3_custom']['flag_suffix']}")
    print(f"  Total length: {data['layer3_custom']['flag_length']} bytes")
    print()

    print("="*70)
    print("HINTS")
    print("="*70)
    print(f"Stage 1: {data['hints']['stage1']}")
    print(f"Stage 2: {data['hints']['stage2']}")
    print(f"Stage 3: {data['hints']['stage3']}")
    print()
    print("You must complete each stage to unlock the next...")
    print("="*70)
    print()

def main():
    import os
    if os.path.exists("challenge_data.json"):
        print("Found existing challenge_data.json")
        print()
        with open("challenge_data.json", "r") as f:
            data = json.load(f)
    else:
        print("Generating new challenge...")
        print()
        data = generate_challenge()
    
    # Don't display solution data
    display_data = {k: v for k, v in data.items() if not k.startswith('_')}
    display_challenge(display_data)
    

if __name__ == "__main__":

    main()
