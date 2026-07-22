import hashlib

def hex_to_wif(private_key_hex, compressed=True):
    """
    Converts a raw hexadecimal private key into Wallet Import Format (WIF).
    
    :param private_key_hex: The 64-character hex string of the private key.
    :param compressed: True for compressed public keys (starts with K or L), 
                       False for uncompressed public keys (starts with 5).
    :return: Base58Check encoded WIF string.
    """
    # 1. Base58 alphabet definition
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Clean and convert the hex string to bytes
    raw_key_bytes = bytes.fromhex(private_key_hex.strip().replace("0x", "").zfill(64))
    
    # 2. Add Mainnet Network Byte (0x80) prefix
    extended_key = b'\x80' + raw_key_bytes
    
    # 3. Add Compressed Flag (0x01) suffix if applicable
    if compressed:
        extended_key += b'\x01'
        
    # 4. Calculate Checksum (First 4 bytes of double-SHA256)
    first_sha = hashlib.sha256(extended_key).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha[:4]
    
    # 5. Append Checksum to the extended key
    final_bytes = extended_key + checksum
    
    # 6. Encode into Base58
    value = int.from_bytes(final_bytes, byteorder='big')
    wif_encoded = ""
    while value > 0:
        value, remainder = divmod(value, 58)
        wif_encoded = base58_alphabet[remainder] + wif_encoded
        
    # Handle leading zero bytes padding if present
    for byte in final_bytes:
        if byte == 0:
            wif_encoded = base58_alphabet[0] + wif_encoded
        else:
            break
            
    return wif_encoded

# ==========================================
# Example Usage
# ==========================================
# Sample private key derived from your recovery logic
sample_private_key_hex = "65b168e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"

# Generate both variants
compressed_wif = hex_to_wif(sample_private_key_hex, compressed=True)
uncompressed_wif = hex_to_wif(sample_private_key_hex, compressed=False)

print(f"Hex Key:      {sample_private_key_hex}\n")
print(f"Compressed WIF (Modern / SegWit):   {compressed_wif}")
print(f"Uncompressed WIF (Legacy):          {uncompressed_wif}")
