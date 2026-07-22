import re

def check_vulnerabilities(report_content):
    """
    Parses a vulnerability report string and evaluates the match counts.
    """
    # Define the regex patterns to capture the match counts for each vulnerability
    patterns = {
        "Reused Nonce": r"Reused Nonce\s*➜\s*Matches:\s*(\d+)",
        "Small K": r"Small K\s*➜\s*Matches:\s*(\d+)",
        "Fault Attack": r"Fault Attack\s*➜\s*Matches:\s*(\d+)"
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
        print(f"[HIGH] Reused Nonce: {reused_nonce_count} matches found! ⚠️ (CRITICAL: Private key may be compromised)")
    else:
        print("[PASS] Reused Nonce: 0 matches found.")

    # Check Small K (High Risk if > 0)
    small_k_count = results.get("Small K", 0)
    if small_k_count > 0:
        print(f"[HIGH] Small K: {small_k_count} matches found! ⚠️ (CRITICAL: Biased or weak nonce used)")
    else:
        print("[PASS] Small K: 0 matches found.")

    # Check Fault Attack (High Risk if > 0)
    fault_attack_count = results.get("Fault Attack", 0)
    if fault_attack_count > 0:
        print(f"[HIGH] Fault Attack: {fault_attack_count} matches found! ⚠️ (CRITICAL: Signature fault injection detected)")
    else:
        print("[PASS] Fault Attack: 0 matches found.")

# Example usage with your provided output
sample_report = """
Vulnerability Matrix Overview:
 • [HIGH] Reused Nonce ➜ Matches: 159
 • [HIGH] Small K ➜ Matches: 0
 • [HIGH] Fault Attack ➜ Matches: 0
"""

if __name__ == "__main__":
    check_vulnerabilities(sample_report)
