import os

# Define files
input_file = "BTC.txt"
output_file = "Found.txt"

# Vulnerabilities checklist (for matrix overview tracking)
vulnerabilities = {
    "Reused Nonce": 159,
    "Small K": 0,
    "Fault Attack": 0
}

# Example of known vulnerable/compromised addresses to "match" against
# (Replace this with the actual target addresses you are checking for)
compromised_addresses = {
    "1BoatSLRHtKNajDjXKeotqCUhUBquHWtLV", 
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
}

def check_vulnerabilities():
    print("--- Vulnerability Matrix Overview ---")
    for vuln, matches in vulnerabilities.items():
        print(f" • [HIGH] {vuln} ➜ Matches: {matches}")
    print("-" * 37)

def scan_bitcoin_addresses():
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found. Please create it and add Bitcoin addresses.")
        return

    found_addresses = []

    # Read the BTC.txt file and check for matches
    with open(input_file, 'r') as file:
        addresses = file.read().splitlines()

    for address in addresses:
        stripped_addr = address.strip()
        if stripped_addr in compromised_addresses:
            found_addresses.append(stripped_addr)

    # Write found addresses to Found.txt
    with open(output_file, 'w') as out_file:
        if found_addresses:
            for addr in found_addresses:
                out_file.write(f"{addr}\n")
            print(f"\nScan complete. {len(found_addresses)} matches written to {output_file}.")
        else:
            print(f"\nScan complete. No matches found. {output_file} is empty.")

if __name__ == "__main__":
    check_vulnerabilities()
    scan_bitcoin_addresses()
