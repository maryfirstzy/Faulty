import os
import re


def check_vulnerabilities_from_file(file_path="BTC.txt"):
    """Reads a vulnerability report from a file and evaluates the match counts."""
    # Ensure the file exists before attempting to read
    if not os.path.exists(file_path):
        print(f"[ERROR] The file '{file_path}' was not found.")
        print("Please create the file in the same directory as this script.")
        return

    # Read the content of BTC.txt
    with open(file_path, "r", encoding="utf-8") as file:
        report_content = file.read()

    # Define the regex patterns to capture the match counts for each vulnerability
    patterns = {
        "Reused Nonce": r"Reused Nonce\s*➜\s*Matches:\s*(\d+)",
        "Small K": r"Small K\s*➜\s*Matches:\s*(\d+)",
        "Fault Attack": r"Fault Attack\s*➜\s*Matches:\s*(\d+)",
    }

    results = {}

    # Extract matches for each vulnerability
    for vuln, pattern in patterns.items():
        match = re.search(pattern, report_content)
        if match:
            results[vuln] = int(match.group(1))
        else:
            results[vuln] = 0

    print("--- Vulnerability Status ---\n")

    # Check Reused Nonce (High Risk if > 0)
    reused_nonce_count = results.get("Reused Nonce", 0)
    if reused_nonce_count > 0:
        print(
            f"[HIGH] Reused Nonce: {reused_nonce_count} matches found! ⚠️ (CRITICAL: Private key may be compromised)"
        )
    else:
        print("[PASS] Reused Nonce: 0 matches found.")

    # Check Small K (High Risk if > 0)
    small_k_count = Antiquated = results.get("Small K", 0)
    if small_k_count > 0:
        print(
            f"[HIGH] Small K: {small_k_count} matches found! ⚠️ (CRITICAL: Biased or weak nonce used)"
        )
    else:
        print("[PASS] Small K: 0 matches found.")

    # Check Fault Attack (High Risk if > 0)
    fault_attack_count = results.get("Fault Attack", 0)
    if fault_attack_count > 0:
        print(
            f"[HIGH] Fault Attack: {fault_attack_count} matches found! ⚠️ (CRITICAL: Signature fault injection detected)"
        )
    else:
        print("[PASS] Fault Attack: 0 matches found.")


if __name__ == "__main__":
    # This will look for 'BTC.txt' in the same folder where the script runs
    check_vulnerabilities_from_file("BTC.txt")
