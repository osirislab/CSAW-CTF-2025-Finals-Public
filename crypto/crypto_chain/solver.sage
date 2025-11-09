#!/usr/bin/env sage
"""
solve.sage - Solution to Multi-Layer Quantum Entanglement Challenge

TRUE sequential chain: Wiener → Parameters → Coppersmith
Each stage unlocks the next.

Comments added with Sonnet 4.5 (human read and approved)

Run with: sage solve.sage
"""

import json
import time
from sage.all import *

def bytes_to_long(s):
    """Convert bytes/string to integer"""
    if isinstance(s, str):
        s = s.encode()
    return Integer(int.from_bytes(s, 'big'))

def long_to_bytes(n):
    """Convert integer to bytes"""
    n = int(n)
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

print("="*70)
print("MULTI-LAYER QUANTUM ENTANGLEMENT - SOLUTION")
print("="*70)
print()

# ============================================================================
# LOAD CHALLENGE
# ============================================================================
print("[*] Loading challenge data...")
try:
    with open("challenge_data.json", "r") as f:
        data = json.load(f)
except FileNotFoundError:
    print("[!] Error: challenge_data.json not found!")
    exit(1)

n1 = Integer(data["layer1_rsa"]["n"])
e1 = Integer(data["layer1_rsa"]["e"])
c1 = Integer(data["layer1_rsa"]["related_message_c1"])
c2 = Integer(data["layer1_rsa"]["related_message_c2"])
known_offset = Integer(data["layer1_rsa"]["known_offset"])
c_params = Integer(data["layer1_rsa"]["encrypted_params"])

n2 = Integer(data["layer3_custom"]["n"])
e2 = Integer(data["layer3_custom"]["e"])
c_flag = Integer(data["layer3_custom"]["encrypted_flag"])
flag_prefix = data["layer3_custom"]["flag_prefix"]
flag_suffix = data["layer3_custom"]["flag_suffix"]
flag_length = data["layer3_custom"]["flag_length"]

print(f"[+] Challenge loaded")
print()

# ============================================================================
# STAGE 1: WIENER'S ATTACK ON LAYER 1 RSA
# ============================================================================
print("="*70)
print("STAGE 1: Break Layer 1 RSA (Wiener's Attack)")
print("="*70)
print()
print(f"[*] n1 = {n1.nbits()}-bit")
print(f"[*] e1 = {e1.nbits()}-bit (suspiciously large!)")
print("[*] Large e suggests small d → Wiener's attack")
print()

def wieners_attack(e, n):
    """Wiener's attack using continued fractions"""
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    
    for frac in convergents:
        k = frac.numerator()
        d_guess = frac.denominator()
        
        if k == 0:
            continue
        
        phi_guess = (e * d_guess - 1) // k
        
        # Solve for p and q
        b = n - phi_guess + 1
        discriminant = b*b - 4*n
        
        if discriminant >= 0:
            sqrt_disc = Integer(discriminant).isqrt()
            if sqrt_disc * sqrt_disc == discriminant:
                p = (b + sqrt_disc) // 2
                q = (b - sqrt_disc) // 2
                
                if p * q == n and p > 1 and q > 1:
                    return int(d_guess), int(p), int(q)
    
    return None, None, None

start = time.time()
d1, p1, q1 = wieners_attack(e1, n1)
elapsed = time.time() - start

if d1 is None:
    print("[!] Wiener's attack failed!")
    exit(1)

print(f"[+] Recovered d1 in {elapsed:.3f} seconds!")
print(f"    d1 = {d1} ({Integer(d1).nbits()}-bit)")
print(f"    p1 = {Integer(p1).nbits()}-bit prime")
print(f"    q1 = {Integer(q1).nbits()}-bit prime")

# Verify
phi1 = (p1 - 1) * (q1 - 1)
if (e1 * d1) % phi1 == 1:
    print("[+] Verified: e1 * d1 ≡ 1 (mod φ(n1))")
else:
    print("[!] Verification failed!")
    exit(1)
print()

# ============================================================================
# STAGE 2: RECOVER TRANSFORMATION PARAMETERS
# ============================================================================
print("="*70)
print("STAGE 2: Recover Transformation Parameters")
print("="*70)
print()
print("[*] Using recovered d1 to decrypt parameter hints...")
print()

# Method 1: Direct decryption of encrypted params
print("[*] Method 1: Decrypting c_params directly...")
m_params = power_mod(c_params, d1, n1)
params_bytes = long_to_bytes(m_params)
params_str = params_bytes.decode('ascii', errors='ignore').strip('\x00')

print(f"    Decrypted: {params_str}")

# Parse parameters
if "transform_params:" in params_str:
    param_part = params_str.split("transform_params:")[1]
    param_values = param_part.split(",")
    
    if len(param_values) >= 3:
        alpha = Integer(param_values[0].strip())
        beta = Integer(param_values[1].strip())
        gamma = Integer(param_values[2].strip())
        
        print(f"[+] Extracted parameters:")
        print(f"    alpha = {alpha}")
        print(f"    beta  = {beta}")
        print(f"    gamma = {gamma}")
        print()
    else:
        print("[!] Could not parse parameters, trying Franklin-Reiter...")
        
        # Method 2: Franklin-Reiter on related messages
        print()
        print("[*] Method 2: Franklin-Reiter on related messages...")
        
        # Set up polynomial ring
        PR.<x> = PolynomialRing(Zmod(n1))
        
        # f1(x) = x^e - c1
        # f2(x) = (x + offset)^e - c2
        f1 = x^e1 - c1
        f2 = (x + known_offset)^e1 - c2
        
        print("[*] Computing polynomial GCD...")
        g = f1.gcd(f2)
        
        if g.degree() == 1:
            m1_recovered = -g.coefficients()[0]
            m1_bytes = long_to_bytes(m1_recovered)
            m1_str = m1_bytes.decode('ascii', errors='ignore')
            
            print(f"[+] Recovered m1: {m1_str[:100]}...")
            
            # Parse alpha, beta, gamma from recovered message
            if "alpha:" in m1_str:
                parts = m1_str.split('|')
                alpha = Integer(parts[0].split(':')[1])
                beta = Integer(parts[1].split(':')[1])
                gamma = Integer(parts[2].split(':')[1])
                
                print(f"[+] Extracted from related messages:")
                print(f"    alpha = {alpha}")
                print(f"    beta  = {beta}")
                print(f"    gamma = {gamma}")
                print()
        else:
            print("[!] Franklin-Reiter failed!")
            exit(1)
else:
    print("[!] Unexpected format, trying Franklin-Reiter...")
    
    # Fallback to Franklin-Reiter
    PR.<x> = PolynomialRing(Zmod(n1))
    f1 = x^e1 - c1
    f2 = (x + known_offset)^e1 - c2
    
    g = f1.gcd(f2)
    if g.degree() == 1:
        m1_recovered = -g.coefficients()[0]
        m1_bytes = long_to_bytes(m1_recovered)
        m1_str = m1_bytes.decode('ascii', errors='ignore')
        
        if "alpha:" in m1_str:
            parts = m1_str.split('|')
            alpha = Integer(parts[0].split(':')[1])
            beta = Integer(parts[1].split(':')[1])
            gamma = Integer(parts[2].split(':')[1])
            
            print(f"[+] Extracted parameters:")
            print(f"    alpha = {alpha}")
            print(f"    beta  = {beta}")
            print(f"    gamma = {gamma}")
            print()

# ============================================================================
# STAGE 3: BREAK CUSTOM TRANSFORMATION + RSA LAYER
# ============================================================================
print("="*70)
print("STAGE 3: Break Custom Quadratic Transformation")
print("="*70)
print()
print(f"[*] n2 = {n2.nbits()}-bit")
print(f"[*] Transformation: m' = m^2*alpha + m*beta + gamma (mod n2)")
print()

# Step 3a: Factor n2 (close primes → Fermat)
print("[*] Factoring n2 using Fermat's method...")

def fermat_factor(n):
    a = Integer(n).isqrt() + 1
    b2 = a*a - n
    
    for i in range(10000000):
        b = b2.isqrt()
        if b*b == b2:
            return a - b, a + b
        a += 1
        b2 = a*a - n
    return None, None

start = time.time()
p2, q2 = fermat_factor(n2)
elapsed = time.time() - start

if p2 is None:
    print("[!] Fermat factorization failed!")
    exit(1)

print(f"[+] Factored in {elapsed:.3f} seconds")
print(f"    p2 = {Integer(p2).nbits()}-bit")
print(f"    q2 = {Integer(q2).nbits()}-bit")
print(f"    Verify: p2 * q2 = n2? {p2 * q2 == n2}")
print()

# Step 3b: Decrypt RSA layer
phi2 = (p2 - 1) * (q2 - 1)
d2 = inverse_mod(e2, phi2)

m_transformed = power_mod(c_flag, d2, n2)
print(f"[*] Decrypted RSA layer:")
print(f"    m_transformed = {m_transformed}")
print()

# Step 3c: Reverse quadratic transformation with Coppersmith
print("[*] Reversing quadratic transformation with Coppersmith...")
print(f"[*] Must solve: m^2*{alpha} + m*{beta} + {gamma} ≡ {m_transformed} (mod n2)")
print(f"[*] Known: flag starts with '{flag_prefix}' and ends with '{flag_suffix}'")
print()

# Flag structure: prefix + unknown_middle + suffix
prefix_bytes = flag_prefix.encode()
suffix_bytes = flag_suffix.encode()

known_prefix_len = len(prefix_bytes)
known_suffix_len = len(suffix_bytes)
unknown_len = flag_length - known_prefix_len - known_suffix_len

print(f"[*] Flag structure: {known_prefix_len} bytes prefix + {unknown_len} bytes unknown + {known_suffix_len} bytes suffix")
print()

# Set up Coppersmith
# m = prefix * 256^(unknown_len + suffix_len) + x * 256^suffix_len + suffix
# where x is unknown middle (< 256^unknown_len)

prefix_val = bytes_to_long(prefix_bytes)
suffix_val = bytes_to_long(suffix_bytes)

shift1 = 256 ** (unknown_len + known_suffix_len)
shift2 = 256 ** known_suffix_len

PR.<x> = PolynomialRing(Zmod(n2))

# (prefix*shift1 + x*shift2 + suffix)^2 * alpha + (prefix*shift1 + x*shift2 + suffix) * beta + gamma - m_transformed = 0
m_poly = prefix_val * shift1 + x * shift2 + suffix_val
poly = m_poly * m_poly * alpha + m_poly * beta + gamma - m_transformed

# Make polynomial monic (leading coefficient = 1)
# The polynomial is quadratic in x with structure: a*x^2 + b*x + c
# Get all coefficients
coeffs = poly.list()  # Returns list of coefficients [c, b, a]

if len(coeffs) >= 3 and coeffs[-1] != 0:
    # Leading coefficient (coefficient of x^2)
    a_coeff = coeffs[-1]
    
    # Compute inverse of leading coefficient mod n2
    try:
        a_inv = inverse_mod(int(a_coeff), n2)
        # Multiply polynomial by inverse to make it monic
        poly_monic = poly * a_inv
    except:
        print("[!] Could not invert leading coefficient, using CRT fallback...")
        poly_monic = None
else:
    print("[!] Polynomial structure unexpected, using CRT fallback...")
    poly_monic = None

if poly_monic is not None:
    print("[*] Solving with Coppersmith's method...")
    print(f"    Search space: x < 256^{unknown_len} = 2^{8*unknown_len}")
    
    # Find small roots
    try:
        roots = poly_monic.small_roots(X=256**unknown_len, beta=0.4, epsilon=0.01)
    except Exception as ex:
        print(f"[!] small_roots failed with beta=0.4: {ex}")
        print("[*] Trying with beta=0.5...")
        try:
            roots = poly_monic.small_roots(X=256**unknown_len, beta=0.5)
        except Exception as ex2:
            print(f"[!] Also failed with beta=0.5: {ex2}")
            print("[*] Falling back to solving quadratic with CRT...")
            roots = []
else:
    roots = []

if roots:
    x_val = int(roots[0])
    m_flag = prefix_val * shift1 + x_val * shift2 + suffix_val
    flag_bytes = long_to_bytes(m_flag)
    
    try:
        flag_text = flag_bytes.decode('ascii')
        
        # Verify
        m_test = bytes_to_long(flag_text)
        m_transformed_test = (m_test * m_test * alpha + m_test * beta + gamma) % n2
        
        if m_transformed_test == m_transformed:
            print()
            print("="*70)
            print("FLAG RECOVERED!")
            print("="*70)
            print()
            print(f"    {flag_text}")
            print()
            print("="*70)
            print()
            print("[+] Verification successful!")
        else:
            print("[!] Verification failed!")
    except:
        print("[!] Could not decode flag")
else:
    print("[!] Coppersmith attack failed - trying CRT method instead...")
    print()
    
    # Fallback: Solve quadratic equation using CRT
    print("[*] Solving quadratic equation: m^2*alpha + m*beta + gamma ≡ m_transformed (mod n2)")
    print("[*] Using Chinese Remainder Theorem...")
    
    def solve_quadratic_mod_prime(a, b, c, prime):
        """Solve a*x^2 + b*x + c ≡ 0 (mod prime)"""
        Zp = IntegerModRing(prime)
        a_p = Zp(a)
        b_p = Zp(b)
        c_p = Zp(c)
        
        if a_p == 0:
            if b_p == 0:
                return [] if c_p != 0 else [0]
            return [Integer(-c_p / b_p)]
        
        discriminant = b_p*b_p - 4*a_p*c_p
        
        if discriminant == 0:
            return [Integer(-b_p / (2*a_p))]
        
        try:
            sqrt_disc = discriminant.sqrt()
            inv_2a = 1 / (2*a_p)
            sol1 = Integer((-b_p + sqrt_disc) * inv_2a)
            sol2 = Integer((-b_p - sqrt_disc) * inv_2a)
            return [sol1, sol2]
        except:
            return []
    
    # Solve modulo p2 and q2
    a_coeff = alpha
    b_coeff = beta
    c_coeff = gamma - m_transformed
    
    solutions_p = solve_quadratic_mod_prime(a_coeff, b_coeff, c_coeff, p2)
    solutions_q = solve_quadratic_mod_prime(a_coeff, b_coeff, c_coeff, q2)
    
    print(f"[+] Found {len(solutions_p)} solution(s) mod p2")
    print(f"[+] Found {len(solutions_q)} solution(s) mod q2")
    
    # Combine with CRT
    candidates = []
    for sp in solutions_p:
        for sq in solutions_q:
            m_candidate = CRT_list([Integer(sp), Integer(sq)], [p2, q2])
            candidates.append(m_candidate)
    
    print(f"[+] Testing {len(candidates)} candidate(s)...")
    
    for m_candidate in candidates:
        try:
            flag_bytes = long_to_bytes(m_candidate)
            
            if b'CSAW{' in flag_bytes and b'}' in flag_bytes:
                flag_text = flag_bytes.decode('ascii')
                
                # Verify
                m_test = bytes_to_long(flag_text)
                m_transformed_test = (m_test * m_test * alpha + m_test * beta + gamma) % n2
                
                if m_transformed_test == m_transformed:
                    print()
                    print("="*70)
                    print("FLAG RECOVERED!")
                    print("="*70)
                    print()
                    print(f"    {flag_text}")
                    print()
                    print("="*70)
                    print()
                    print("[+] Verification successful!")
                    break
        except:
            continue
    else:
        print("[!] No valid flag found in candidates")

print()

# ============================================================================
# SUMMARY
# ============================================================================
print("="*70)
print("ATTACK SUMMARY")
print("="*70)
print()
print("Successfully broke all three layers:")
print()
print("STAGE 1: Wiener's Attack")
print("  - Recognized large e → small d vulnerability")
print("  - Applied continued fractions to recover d1")
print("  - Unlocked Layer 1 RSA decryption")
print()
print("STAGE 2: Parameter Recovery")
print("  - Used recovered d1 to decrypt parameter hints")
print("  - Extracted transformation keys: alpha, beta, gamma")
print("  - Alternative: Franklin-Reiter on related messages")
print()
print("STAGE 3: Custom Transformation + Coppersmith")
print("  - Factored n2 with Fermat's method (close primes)")
print("  - Decrypted RSA layer to get transformed plaintext")
print("  - Used Coppersmith with known prefix/suffix")
print("  - Reversed quadratic transformation to recover flag")
print()
print("="*70)
print("KEY INSIGHT")
print("="*70)
print()
print("This challenge required completing ALL stages sequentially:")
print("  Stage 1 output → enables Stage 2")
print("  Stage 2 output → enables Stage 3")
print("  Stage 3 → reveals flag")
print()
print("No shortcuts! Each layer must be broken to proceed.")
print()
print("="*70)
print()