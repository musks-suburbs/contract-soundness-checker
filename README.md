# README.md
# contract-soundness-checker

Description
A simple CLI tool for checking the "soundness" of smart contracts: it computes the on-chain bytecode keccak hash and compares it with a reference value. Useful for verifying the immutability of L1 contracts related to private L2/zk projects (Aztec, Zama), as well as for general Web3 auditing tasks.

What it does
1) Connects to an EVM-compatible RPC.  
2) Retrieves the contract bytecode by address.  
3) Computes the keccak hash of the bytecode.  
4) Optionally compares it with the expected hash from a manifest (or provided directly).  
5) Prints the result and process exit code (0 — all OK, 2 — mismatches found).

Installation
1) Requires Python 3.9+  
2) Install dependencies:  
   pip install web3  
3) Set the RPC:  
   either export the environment variable RPC_URL,  
   or specify --rpc when running (works with any EVM RPC: Ethereum, L2, devnet, etc.)

Manifest file
JSON format: { "address": "expected_hash" }.  
If the expected hash is set to the word “keccak”, the script only prints the computed hash without comparing.  
Example content:  
{
  "0x00000000219ab540356cBB839Cbe05303d7705Fa": "0xYOUR_EXPECTED_HASH_OR_use_keccak"
}

Run: single address
   python app.py --address 0x00000000219ab540356cBB839Cbe05303d7705Fa  
Will print only the computed hash.

Run: address + expected hash
   python app.py --address 0x00000000219ab540356cBB839Cbe05303d7705Fa --expected 0xabc123...

Run: using manifest
   python app.py --manifest manifest.json

Specify RPC directly
   python app.py --rpc https://mainnet.infura.io/v3/YOUR_KEY --address 0x...

Parameters
--rpc        RPC node URL (default taken from RPC_URL or Infura placeholder)  
--manifest   Path to JSON manifest (if --address is not provided)  
--address    Single contract address to check  
--expected   Expected hash for --address (if not specified — prints only the hash)  
--timeout    HTTP timeout in seconds (default: 30)

Expected output
On successful connection and computation, you’ll see:  
🔧 Smart Contract Soundness Checker  
🔗 RPC: <your RPC>  
🔍 0x... -> code hash: 0x...  
🎯 Soundness verified for all targets (no mismatches).

If at least one contract doesn’t match:  
🔍 0x... -> code hash: 0x... | expected: 0x... | ❌ MISMATCH  
🚨 Soundness check failed (one or more mismatches).  
The process exit code will be 2, which is convenient for CI pipelines.

Integration with Aztec/Zama and private L2s
Many private/zk solutions (e.g., Aztec) deploy critical contracts on L1 (Ethereum or other base networks). Add those addresses to your manifest and store reference hashes as part of your repository. For development networks or custom deployments, simply specify their RPC and addresses.  
For Zama-based projects (FHE/zk integrations), the same logic applies: verify the immutability of critical on-chain modules.

Practical use cases
— Integrity control of upgradeable proxies (implementation contracts) in production.  
— Quick soundness check before release: compare hashes with canonical references from Git.  
— Monitoring of L1 bridges a
