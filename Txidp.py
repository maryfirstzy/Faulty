import urllib.request
import json

def fetch_and_analyze_tx(txid, target_input_index):
    """
    Fetches raw transaction properties and structure to map out signature data.
    """
    print(f"Connecting to blockchain API for TXID: {txid}...")
    
    # 1. Fetch JSON details to identify the script type of the input
    json_url = f"https://mempool.space/api/tx/{txid}"
    try:
        with urllib.request.urlopen(json_url) as response:
            tx_data = json.loads(response.read().decode())
    except Exception as e:
        return f"Error fetching transaction data: {e}"

    if target_input_index >= len(tx_data['vin']):
        return f"Error: Target input index {target_input_index} out of range (Total inputs: {len(tx_data['vin'])})"

    target_input = tx_data['vin'][target_input_index]
    
    print("\n=== Input Analysed ===")
    print(f"Analyzing Input Index: {target_input_index}")
    print(f"Previous Output (UTXO Spent): {target_input['txid']}:{target_input['vout']}")
    
    # Check if transaction input uses SegWit (Witness data present)
    is_segwit = "witness" in target_input and len(target_input["witness"]) > 0
    print(f"Script Class: {'SegWit (BIP143)' if is_segwit else 'Legacy (BIP115/P2PKH)'}")
    
    # 2. Fetch the raw hex string of the transaction (required to build the pre-image hash z)
    hex_url = f"https://mempool.space/api/tx/{txid}/hex"
    try:
        with urllib.request.urlopen(hex_url) as response:
            raw_tx_hex = response.read().decode().strip()
    except Exception as e:
        return f"Error fetching raw transaction hex: {e}"

    return {
        "is_segwit": is_segwit,
        "raw_tx_hex": raw_tx_hex,
        "input_details": target_input
    }

# ==========================================
# Run Fetcher
# ==========================================
TXID = "32fdac369d47feef3597f48a31140ab8bbb12ee6d509713eaa87b36e7b8c4e7c"
INPUT_INDEX = 24

tx_analysis = fetch_and_analyze_tx(TXID, INPUT_INDEX)

if isinstance(tx_analysis, dict):
    print("\n✅ Raw Transaction Hex Successfully Retrieved.")
    print("Length of Hex:", len(tx_analysis['raw_tx_hex']), "characters")
else:
    print(tx_analysis)
