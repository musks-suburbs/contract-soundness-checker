# app.py
import os
import sys
import json
import argparse
from typing import Dict, Tuple
from web3 import Web3

DEFAULT_RPC = os.environ.get("RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")

# Built-in sample manifest with one known contract (replace or extend as needed)
BUILTIN_MANIFEST = {
    # Ethereum Deposit Contract (example)
    "0x00000000219ab540356cBB839Cbe05303d7705Fa": "keccak"
    # Add more addresses here; set value to "keccak" to compute and print only,
    # or to a specific 0x-hash string to compare for equality.
}

def load_manifest(path: str) -> Dict[str, str]:
    if not path:
        return BUILTIN_MANIFEST
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Manifest must be a JSON object mapping address -> expected_hash or 'keccak'")
    return data

def checksum(address: str) -> str:
    return Web3.to_checksum_address(address)

def get_code_hash(w3: Web3, address: str) -> str:
    code = w3.eth.get_code(checksum(address))
    return Web3.keccak(code).hex()

def verify(w3: Web3, address: str, expected: str) -> Tuple[str, bool]:
    h = get_code_hash(w3, address)
    if expected == "keccak":
        return h, True  # informational only
    return h, (h.lower() == expected.lower())

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Smart Contract Soundness Checker — computes on-chain bytecode keccak hash and optionally compares with an expected baseline (useful for L1 contracts related to Aztec, Zama, and general web3)."
    )
    p.add_argument("--rpc", default=DEFAULT_RPC, help="EVM-compatible RPC URL (default: env RPC_URL or Infura placeholder)")
    p.add_argument("--manifest", help="Path to JSON manifest {address: expected_hash|'keccak'}")
    p.add_argument("--address", help="Single contract address to check (overrides manifest if provided)")
    p.add_argument("--expected", help="Expected 0x… hash for --address; if omitted, prints computed hash only")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": args.timeout}))
    if not w3.is_connected():
        print("❌ RPC connection failed. Check --rpc or RPC_URL.")
        sys.exit(1)

    print("🔧 Smart Contract Soundness Checker")
    print(f"🔗 RPC: {args.rpc}")

    targets: Dict[str, str] = {}

    if args.address:
        if args.expected:
            targets[args.address] = args.expected
        else:
            targets[args.address] = "keccak"
    else:
        try:
            targets = load_manifest(args.manifest)
        except Exception as e:
            print(f"❌ Failed to load manifest: {e}")
            sys.exit(1)

    if not targets:
        print("⚠️ No targets to verify.")
        sys.exit(0)

    all_ok = True
    for addr, expected in targets.items():
        try:
            h, ok = verify(w3, addr, expected)
            if expected == "keccak":
                print(f"🔍 {addr} -> code hash: {h}")
            else:
                status = "✅ MATCH" if ok else "❌ MISMATCH"
                print(f"🔍 {addr} -> code hash: {h} | expected: {expected} | {status}")
                all_ok = all_ok and ok
        except Exception as e:
            print(f"❌ {addr} -> error: {e}")
            all_ok = False

    if all_ok:
        print("🎯 Soundness verified for all targets (no mismatches).")
        sys.exit(0)
    else:
        print("🚨 Soundness check failed (one or more mismatches).")
        sys.exit(2)

if __name__ == "__main__":
    main()
