# app.py (optimized)
import os
import sys
import json
import argparse
from typing import Dict, Tuple, Optional, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from web3 import Web3
from web3.exceptions import TransactionNotFound

DEFAULT_RPC = os.environ.get("RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")

# Built-in sample manifest with one known contract (replace or extend as needed)
BUILTIN_MANIFEST: Dict[str, str] = {
    # Ethereum Deposit Contract (example)
    "0x00000000219ab540356cBB839Cbe05303d7705Fa": "keccak"
    # Add more addresses here; set value to "keccak" to compute and print only,
    # or to a specific 0x-hash string to compare for equality.
}

def load_manifest(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return BUILTIN_MANIFEST
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Manifest must be a JSON object mapping address -> expected_hash or 'keccak'")
    # Normalize keys (addresses) to strings and values to strings
    norm: Dict[str, str] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError("Manifest entries must be strings: {address: expected_hash|'keccak'}")
        norm[k] = v
    return norm

def checksum(w3: Web3, address: str) -> str:
    try:
        return w3.to_checksum_address(address)
    except ValueError as e:
        raise ValueError(f"Invalid address: {address}") from e

def normalize_expected(expected: str) -> str:
    """
    Normalize expected hash to 0x-prefixed lowercase if provided.
    Allows 'keccak' sentinel to pass through unchanged.
    """
    if expected == "keccak":
        return expected
    h = expected.lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != 64:
        raise ValueError(f"Expected hash must be 32-byte hex (64 chars), got length {len(h)}")
    # Return with 0x prefix restored
    return "0x" + h

def get_code_hash(w3: Web3, address: str) -> str:
    code = w3.eth.get_code(checksum(w3, address))
    # Empty bytecode -> EOA or precompile without code
    return Web3.keccak(code).hex() if code is not None else Web3.keccak(b"").hex()

def verify(w3: Web3, address: str, expected: str) -> Tuple[str, Optional[bool]]:
    """
    Returns (computed_hash, is_match)
    - is_match is None when expected == 'keccak' (informational only)
    """
    computed = get_code_hash(w3, address)
    if expected == "keccak":
        return computed, None
    expected_norm = normalize_expected(expected)
    return computed, (computed.lower() == expected_norm.lower())

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Smart Contract Soundness Checker — computes on-chain bytecode keccak hash and "
            "optionally compares with an expected baseline (useful for L1 contracts related "
            "to Aztec, Zama, and general web3)."
        )
    )
    p.add_argument("--rpc", default=DEFAULT_RPC, help="EVM-compatible RPC URL (default: env RPC_URL or Infura placeholder)")
    p.add_argument("--manifest", help="Path to JSON manifest {address: expected_hash|'keccak'}")
    p.add_argument("--address", help="Single contract address to check (overrides manifest if provided)")
    p.add_argument("--expected", help="Expected 0x… hash for --address; if omitted, prints computed hash only")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    p.add_argument("--concurrency", type=int, default=min(8, (os.cpu_count() or 4)), help="Number of concurrent requests (default: up to 8)")
    return p.parse_args()

def build_targets(args: argparse.Namespace) -> Dict[str, str]:
    if args.address:
        return {args.address: (args.expected if args.expected else "keccak")}
    return load_manifest(args.manifest)

def print_header(rpc: str) -> None:
    print("🔧 Smart Contract Soundness Checker")
    print(f"🔗 RPC: {rpc}")

def process_target(w3: Web3, addr: str, expected: str) -> Tuple[str, str, Optional[bool], Optional[str]]:
    """
    Returns (address, computed_hash, is_match, error_message)
    is_match=None when informational only, or if error occurs (then error_message set).
    """
    try:
        # Normalize once (fast fail on invalid expected hash)
        exp_norm = expected if expected == "keccak" else normalize_expected(expected)
        computed, is_match = verify(w3, addr, exp_norm)
        return addr, computed, is_match, None
    except Exception as e:
        return addr, "", None, str(e)

def run_parallel(w3: Web3, targets: Dict[str, str], concurrency: int) -> Iterable[Tuple[str, str, Optional[bool], Optional[str]]]:
    if concurrency <= 1 or len(targets) == 1:
        for a, e in targets.items():
            yield process_target(w3, a, e)
        return

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {
            ex.submit(process_target, w3, addr, expected): addr
            for addr, expected in targets.items()
        }
        for fut in as_completed(futures):
            yield fut.result()

def main() -> None:
    args = parse_args()
    # Single shared provider for all requests
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": args.timeout}))

    if not w3.is_connected():
        print("❌ RPC connection failed. Check --rpc or RPC_URL.")
        sys.exit(1)

    print_header(args.rpc)

    try:
        targets = build_targets(args)
    except Exception as e:
        print(f"❌ Failed to load targets: {e}")
        sys.exit(1)

    if not targets:
        print("⚠️ No targets to verify.")
        sys.exit(0)

    all_ok = True
    for addr, computed, is_match, error in run_parallel(w3, targets, args.concurrency):
        expected = targets[addr]
        if error:
            print(f"❌ {addr} -> error: {error}")
            all_ok = False
            continue

        if is_match is None:
            # informational only
            print(f"🔍 {addr} -> code hash: {computed}")
        else:
            status = "✅ MATCH" if is_match else "❌ MISMATCH"
            exp_display = expected if expected == "keccak" else normalize_expected(expected)
            print(f"🔍 {addr} -> code hash: {computed} | expected: {exp_display} | {status}")
            all_ok = all_ok and is_match

    if all_ok:
        print("🎯 Soundness verified for all targets (no mismatches).")
        sys.exit(0)
    else:
        print("🚨 Soundness check failed (one or more mismatches).")
        sys.exit(2)

# pip install ens
from ens import ENS
w3.ens = ENS.from_web3(w3)
resolved = w3.ens.address(name_or_address) or name_or_address
if __name__ == "__main__":
    main()
