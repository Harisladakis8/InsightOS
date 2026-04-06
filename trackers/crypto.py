import re

def track_crypto(address: str):
    btc = re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", address)
    eth = re.match(r"^0x[a-fA-F0-9]{40}$", address)

    crypto_type = "Unknown"
    if btc:
        crypto_type = "Bitcoin"
    elif eth:
        crypto_type = "Ethereum"

    return {
        "address": address,
        "type": crypto_type,
        "valid": crypto_type != "Unknown"
    }
