import collections

def check_cryptographic_vulnerabilities(signature_logs):
    """
    Analyzes a list of transaction/signature dictionaries for cryptographic vulnerabilities.
    
    Expected log format: 
    {'tx_id': str, 'nonce': int, 'k_value': int, 'fault_injected': bool}
    """
    results = {
        "reused_nonce": 0,
        "small_k": 0,
        "fault_attack": 0,
        "flagged_txs": collections.defaultdict(list)
    }
    
    nonce_tracker = collections.defaultdict(list)

    for log in signature_logs:
        tx_id = log['tx_id']
        nonce = log['nonce']
        k_value = log['k_value']
        fault_injected = log.get('fault_injected', False)

        # 1. Check for Reused Nonce (Matches > 1 signifies reuse)
        nonce_tracker[nonce].append(tx_id)
        if len(nonce_tracker[nonce]) > 1:
            results["reused_nonce"] += 1
            results["flagged_txs"][tx_id].append("Reused Nonce")

        # 2. Check for Small K (e.g., k < 128 bits, depending on standard)
        # Using a representative threshold for small 'k'
        if k_value < 2**128:
            results["small_k"] += 1
            results["flagged_txs"][tx_id].append("Small K")

        # 3. Check for Fault Attack
        if fault_injected:
            results["fault_attack"] += 1
            results["flagged_txs"][tx_id].append("Fault Attack")

    print("--- Vulnerability Matrix Overview ---")
    print(f" • [HIGH] Reused Nonce ➜ Matches: {results['reused_nonce']}")
    print(f" • [HIGH] Small K ➜ Matches: {results['small_k']}")
    print(f" • [HIGH] Fault Attack ➜ Matches: {results['fault_attack']}")
    
    return results

# --- Example Usage ---
# Dummy data simulating signature generation records
sample_logs = [
    {'tx_id': 'tx_001', 'nonce': 4294967295, 'k_value': 54321, 'fault_injected': False},
    {'tx_id': 'tx_002', 'nonce': 1234567890, 'k_value': 2**150, 'fault_injected': True}, # Fault
    {'tx_id': 'tx_003', 'nonce': 4294967295, 'k_value': 9999, 'fault_injected': False},  # Reused Nonce
    {'tx_id': 'tx_004', 'nonce': 1111111111, 'k_value': 2**256, 'fault_injected': False}
]

audit_results = check_cryptographic_vulnerabilities(sample_logs)
