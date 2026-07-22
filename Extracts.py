import hashlib

def extract_rsz(der_sig_hex, message_bytes=None):
    """
    Extracts r, s, and z from a DER-encoded signature hex string.
    
    :param der_sig_hex: The hex string of the DER signature (usually ends with a sighash byte).
    :param message_bytes: Optional message bytes to compute the z (hash value).
    :return: A dictionary containing r, s, and z in hex and integer formats.
    """
    # Clean the hex string
    der_sig = bytes.fromhex(der_sig_hex.strip())
    
    # 1. Parse and isolate the Sighash byte if present (common in Bitcoin/Crypto)
    # Standard DER signatures start with 0x30. If it has an extra trailing byte, it's the sighash.
    sighash_byte = None
    if len(der_sig) > 2 and der_sig[0] == 0x30:
        # If the declared length plus 2 equals len-1, the last byte is sighash
        declared_len = der_sig[1]
        if declared_len == len(der_sig) - 3:
            sighash_byte = der_sig[-1]
            der_sig = der_sig[:-1]

    # 2. Extract r and s via DER decoding rules
    if der_sig[0] != 0x30:
        raise ValueError("Invalid DER signature format: Must start with 0x30")
        
    # Index tracking pointers
    idx = 2 
    
    # Extract R
    if der_sig[idx] != 0x02:
        raise ValueError("Invalid DER format for r")
    r_len = der_sig[idx + 1]
    r_bytes = der_sig[idx + 2 : idx + 2 + r_len]
    
    # Extract S
    idx += 2 + r_len
    if der_sig[idx] != 0x02:
        raise ValueError("Invalid DER format for s")
    s_len = der_sig[idx + 1]
    s_bytes = der_sig[idx + 2 : idx + 2 + s_len]
    
    # Convert byte arrays to standard integers
    r_int = int.from_bytes(r_bytes, byteorder='big')
    s_int = int.from_bytes(s_bytes, byteorder='big')
    
    # 3. Calculate Z (The message hash)
    # If no custom message is provided, a placeholder or standard double-SHA256 is used
    if message_bytes:
        # Standard Bitcoin double SHA256 of the message context
        z_bytes = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
        z_int = int.from_bytes(z_bytes, byteorder='big')
    else:
        z_int = None

    return {
        "r_hex": hex(r_int),
        "s_hex": hex(s_int),
        "z_hex": hex(z_int) if z_int else "Provide message_bytes to compute z",
        "r_int": r_int,
        "s_int": s_int,
        "z_int": z_int,
        "sighash_byte": hex(sighash_byte) if sighash_byte else "None"
    }

# ==========================================
# Example Usage
# ==========================================
# A typical Bitcoin DER signature hex string (includes 0x01 sighash at the end)
sample_sig_hex = "304402207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a002200a963d693c008f0f8016cfc7861c7f5d8c4e11e11725f8be747bb77d8755f1b801"
sample_message = b"Transaction_Data_To_Sign"

data = extract_rsz(sample_sig_hex, sample_message)

print(f"R (Hex): {data['r_hex']}\n")
print(f"S (Hex): {data['s_hex']}\n")
print(f"Z (Hex): {data['z_hex']}\n")
print(f"Sighash: {data['sighash_byte']}")
