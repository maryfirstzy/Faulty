import hashlib
import random

# secp256k1 Curve Constants
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798

def simulate_ecdsa_sign_with_fault(z, private_key, fault_type=None):
    """
    Simulates an ECDSA signature, with an optional injected fault.
    For demonstration purposes, this uses a simplified model to show how 
    mathematical relations shift under algebraic/hardware faults.
    """
    # Generate the secret nonce k
    k = random.randint(1, SECP256K1_N - 1)
    
    # Calculate r (normally via elliptic curve multiplication r = (k * G).x)
    # Using a deterministic mapping here for raw math clarity
    r = (k * SECP256K1_G_X) % SECP256K1_N
    
    if fault_type == "nonce_glitch":
        # Simulate a hardware fault where the nonce bits are altered
        # AFTER r was already computed, changing the k used in the s calculation.
        k_faulted = k ^ 0xFFFFFFFF  # Flipping the lower 32 bits
        s = (pow(k_faulted, -1, SECP256K1_N) * (z + r * private_key)) % SECP256K1_N
        return r, s
        
    # Standard signature calculation: s = k^-1 * (z + r * d) mod n
    s = (pow(k, -1, SECP256K1_N) * (z + r * private_key)) % SECP256K1_N
    return r, s

def forge_shared_s_vulnerability(private_key, z1, z2):
    """
    Demonstrates the theoretical mathematical structure of a signature pair 
    where 's' remains identical but 'r' and 'z' vary due to a specific state fault.
    """
    # Base valid signature for message 1
    r1, s1 = simulate_ecdsa_sign_with_fault(z1, private_key)
    
    # Under a specific signing loop fault or implementation flaw where s is fixed
    # or forced by a signing state machine glitch, we calculate the forced r2
    # to maintain mathematical consistency under the target conditions.
    s2 = s1  # Forcing the same 's'
    
    # For a shared 's', the mathematical relation dictates the mutated r2 component:
    # r2 = (s1 * k2 - z2) * d^-1 mod n
    k2 = random.randint(1, SECP256K1_N - 1)
    r2 = ((s2 * k2 - z2) * pow(private_key, -1, SECP256K1_N)) % SECP256K1_N
    
    return (r1, s1, z1), (r2, s2, z2)

# ==========================================
# Execution & Analysis
# ==========================================
mock_private_key = 0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
msg1_z = int(hashlib.sha256(b"Transaction A").hexdigest(), 16)
msg2_z = int(hashlib.sha256(b"Transaction B").hexdigest(), 16)

sig1, sig2 = forge_shared_s_vulnerability(mock_private_key, msg1_z, msg2_z)

print("--- Signature 1 (Valid State) ---")
print(f"r1: {hex(sig1[0])}")
print(f"s1: {hex(sig1[1])}")
print(f"z1: {hex(sig1[2])}\n")

print("--- Signature 2 (Faulted State) ---")
print(f"r2: {hex(sig2[0])}")
print(f"s2: {hex(sig2[1])}")
print(f"z2: {hex(sig2[2])}\n")

print("--- Verification Check ---")
print(f"s1 equals s2: {sig1[1] == sig2[1]}")
print(f"r1 equals r2: {sig1[0] == sig2[0]}")
print(f"z1 equals z2: {sig1[2] == sig2[2]}")
