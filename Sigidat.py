import os

# Define I/O files
INPUT_FILE = "BTC.txt"
OUTPUT_FILE = "Found.txt"

def parse_transaction_data(file_path):
    """
    Parses signature parameters from the file.
    Expected file format per line:
    address,public_key_hex,r_hex,s1_hex,z1_hex,s2_hex,z2_hex
    (Note: s2 and z2 are only needed to detect reused nonces across two transactions)
    """
    records = []
    if not os.path.exists(file_path):
        print(f"[-] Error: {file_path} not found. Creating a blank template.")
        with open(file_path, "w") as f:
            f.write("# address,pubkey,r,s1,z1,s2,z2\n")
        return records

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 7:
                records.append({
                    "address": parts[0],
                    "pubkey": parts[1],
                    "r": int(parts[2], 16),
                    "s1": int(parts[3], 16),
                    "z1": int(parts[4], 16),
                    "s2": int(parts[5], 16),
                    "z2": int(parts[6], 16)
                })
    return records

def scan_vulnerabilities():
    # secp256k1 Curve Order (N)
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    records = parse_transaction_data(INPUT_FILE)
    if not records:
        print("[-] No records to scan. Please populate BTC.txt with signature data.")
        return

    matrix = {
        "Reused Nonce": 0,
        "Small K": 0,
        "Fault Attack": 0
    }
    
    found_vulnerable = []

    for tx in records:
        vuln_detected = False
        reasons = []

        # 1. Math for Reused Nonce
        # If two different messages (z1 != z2) use the same R, the nonce k was reused.
        if tx["r"] > 0 and tx["s1"] != tx["s2"] and tx["z1"] != tx["z2"]:
            matrix["Reused Nonce"] += 1
            vuln_detected = True
            reasons.append("Reused Nonce")

        # 2. Math for Small K
        # If the secret nonce 'k' is small, 'R' will fall into a specific low range.
        # This checks if R matches a known small-k signature pattern.
        if tx["r"] < 0x10000000000000000:  # Arbitrary low threshold for demonstration
            matrix["Small K"] += 1
            vuln_detected = True
            reasons.append("Small K")

        # 3. Math for Fault Attack (Signatures with identical R but one is corrupted)
        # If s1 and s2 share R, but the message hashes are identical (z1 == z2), 
        # a hardware fault occurred during one of the calculations.
        if tx["r"] > 0 and tx["s1"] != tx["s2"] and tx["z1"] == tx["z2"]:
            matrix["Fault Attack"] += 1
            vuln_detected = True
            reasons.append("Fault Attack")

        if vuln_detected:
            found_vulnerable.append(f"{tx['address']} | Threats: {', '.join(reasons)}")

    # Print Summary Matrix
    print("\nVulnerability Matrix Overview:")
    for threat, count in matrix.items():
        print(f" • [HIGH] {threat} ➜ Matches: {count}")

    # Write findings to Found.txt
    with open(OUTPUT_FILE, "w") as out:
        if found_vulnerable:
            for item in found_vulnerable:
                out.write(item + "\n")
            print(f"\n[+] Scan complete. {len(found_vulnerable)} vulnerable targets logged to {OUTPUT_FILE}.")
        else:
            out.write("No vulnerabilities found.")
            print(f"\n[+] Scan complete. Clean results. Logged to {OUTPUT_FILE}.")

if __name__ == "__main__":
    scan_vulnerabilities()
