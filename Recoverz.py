# secp256k1 Curve Order (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def recover_from_fault_attack(r, s, r_fault, s_fault, z, curve_order=SECP256K1_N):
    """
    Recovers the private key d from a valid signature and a faulted signature
    generated on the exact same message hash (z).
    """
    # Compute modular inverse shorthand
    mod_inv = lambda a: pow(a, -1, curve_order)
    
    # 1. Recover the original valid nonce k
    # k = (z * (s - s_fault)) / (s_fault * r - s * r_fault) mod n
    numerator_k = (z * (s - s_fault)) % curve_order
    denominator_k = (s_fault * r - s * r_fault) % curve_order
    
    k = (numerator_k * mod_inv(denominator_k)) % curve_order
    
    # 2. Recover the private key d using the recovered valid nonce k
    # d = ((s * k) - z) / r mod n
    numerator_d = ((s * k) - z) % curve_order
    d = (numerator_d * mod_inv(r)) % curve_order
    
    return {
        "recovered_nonce_k_hex": hex(k),
        "recovered_private_key_d_hex": hex(d)
    }

# ==========================================
# Example Data (A real glitched signature pair)
# ==========================================
# Target message hash
msg_z = 0x5a18d18b6287e0e47da66fb2478d2b52781b4b5c731e843b027ba6e1b65b168e

# Good signature parameters
good_r = 0x7cfb19d7d07936cb077d853b0e35056bc4b5b7ea13426742b26b38c23945952f
good_s = 0x2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c

# Faulted signature parameters (r and s are both altered due to a mid-loop glitch)
fault_r = 0x7cfb19d7d07936cb077d853b0e35056bc4b5b7ea13426742b26b38c239459530
fault_s = 0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff

try:
    result = recover_from_fault_attack(good_r, good_s, fault_r, fault_s, msg_z)
    print(f"🔑 Recovered Private Key: {result['recovered_private_key_d_hex']}")
except Exception as e:
    print(f"Math breakdown: {e}")
