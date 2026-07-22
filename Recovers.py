# secp256k1 Curve Order (n) used by Bitcoin
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def modular_inverse(a, m):
    """Computes the modular multiplicative inverse of a modulo m."""
    return pow(a, -1, m)

def recover_private_key(r, s1, z1, s2, z2, curve_order=SECP256K1_N):
    """
    Recovers the private key d when the same nonce k (resulting in identical r)
    is used to sign two different messages.
    """
    if s1 == s2:
        raise ValueError("s1 and s2 cannot be identical; signatures must be unique.")
    
    # 1. Recover the secret nonce k
    # k = (z1 - z2) / (s1 - s2) mod n
    numerator_k = (z1 - z2) % curve_order
    denominator_k = (s1 - s2) % curve_order
    k = (numerator_k * modular_inverse(denominator_k, curve_order)) % curve_order
    
    # 2. Recover the private key d using signature 1
    # d = ((s1 * k) - z1) / r mod n
    numerator_d = ((s1 * k) - z1) % curve_order
    denominator_d = r % curve_order
    d = (numerator_d * modular_inverse(denominator_d, curve_order)) % curve_order
    
    return {
        "recovered_nonce_k_hex": hex(k),
        "private_key_d_hex": hex(d),
        "private_key_d_int": d
    }

# ==========================================
# Example Test Case (Toy Parameters)
# ==========================================
# Shared 'r' component from two unique signatures
flagged_r = 0x7cfb19d7d07936cb077d853b0e35056bc4b5b7ea13426742b26b38c23945952f

# Signature 1 data
sig1_s = 0x5a18d18b6287e0e47da66fb2478d2b52781b4b5c731e843b027ba6e1b65b168e
msg1_z = 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b

# Signature 2 data
sig2_s = 0x3d82a17c6b54e3f20a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f
msg2_z = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

try:
    result = recover_private_key(flagged_r, sig1_s, msg1_z, sig2_s, msg2_z)
    print(f"Nonce (k): {result['recovered_nonce_k_hex']}\n")
    print(f"✅ Recovered Private Key (d): {result['private_key_d_hex']}")
except ValueError as e:
    print(f"Error: {e}")
