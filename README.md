# EVM Contract Inspector

A read-only command-line inspector for EVM addresses and smart contracts.

It checks whether an address has bytecode, reports bytecode size and SHA-256 fingerprint, and looks for common proxy patterns including EIP-1967 implementation storage and EIP-1167 minimal proxies.

## Features

- Contract vs EOA detection
- Runtime bytecode size
- SHA-256 bytecode fingerprint
- EIP-1967 implementation-slot inspection
- EIP-1167 minimal-proxy target detection
- Latest chain block height
- Human-readable or JSON output
- No wallet or private key required
- Standard-library only

## Requirements

- Python 3.10+

## Quick start

```bash
git clone https://github.com/SamAlpha1/EVMContractInspector.git
cd EVMContractInspector
python inspect_contract.py --rpc https://ethereum-rpc.publicnode.com --address 0xCONTRACT_ADDRESS
```

JSON output:

```bash
python inspect_contract.py --rpc https://ethereum-rpc.publicnode.com --address 0xCONTRACT_ADDRESS --json
```

Or set an RPC endpoint in the environment:

```bash
cp .env.example .env
export RPC_URL="https://ethereum-rpc.publicnode.com"
python inspect_contract.py --address 0xCONTRACT_ADDRESS
```

## Important

Proxy detection is heuristic and read-only. A positive result indicates a common proxy pattern or populated implementation slot; it is not a full security audit.

---

## More from SamAlpha1

Before running unfamiliar GitHub or Web3 code, scan the account and its public repositories with **[GitHub Trust Auditor](https://samalpha1.github.io/GitHubTrustAuditor/)**.

Maintained by **[SamAlpha1](https://github.com/SamAlpha1)** · Follow **[@samalpha_ on X](https://x.com/samalpha_)**
