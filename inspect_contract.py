#!/usr/bin/env python3
"""Read-only EVM contract and proxy inspector."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from typing import Any
from urllib import request

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
MINIMAL_PROXY_PREFIX = "363d3d373d3d3d363d73"
MINIMAL_PROXY_SUFFIX = "5af43d82803e903d91602b57fd5bf3"


def rpc_call(url: str, method: str, params: list[Any], timeout: float) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "EVMContractInspector/1.0"})
    with request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    if "error" in body:
        raise RuntimeError(body["error"])
    return body.get("result")


def storage_address(value: str | None) -> str | None:
    if not value or value in ("0x", "0x0"):
        return None
    raw = value[2:].rjust(64, "0")
    address = raw[-40:]
    if int(address, 16) == 0:
        return None
    return "0x" + address


def detect_minimal_proxy(code_hex: str) -> str | None:
    raw = code_hex[2:].lower() if code_hex.startswith("0x") else code_hex.lower()
    idx = raw.find(MINIMAL_PROXY_PREFIX)
    if idx < 0:
        return None
    start = idx + len(MINIMAL_PROXY_PREFIX)
    target = raw[start : start + 40]
    suffix = raw[start + 40 : start + 40 + len(MINIMAL_PROXY_SUFFIX)]
    if len(target) == 40 and suffix == MINIMAL_PROXY_SUFFIX:
        return "0x" + target
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect EVM bytecode and common proxy patterns.")
    parser.add_argument("--rpc", default=os.getenv("RPC_URL"), help="EVM JSON-RPC URL or set RPC_URL.")
    parser.add_argument("--address", required=True, help="EVM address to inspect.")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.rpc:
        raise SystemExit("Provide --rpc or set RPC_URL.")
    if not ADDRESS_RE.fullmatch(args.address):
        raise SystemExit("Invalid EVM address. Expected 0x followed by 40 hex characters.")

    code = rpc_call(args.rpc, "eth_getCode", [args.address, "latest"], args.timeout) or "0x"
    block_number = int(rpc_call(args.rpc, "eth_blockNumber", [], args.timeout), 16)
    chain_id = int(rpc_call(args.rpc, "eth_chainId", [], args.timeout), 16)
    has_code = code not in ("0x", "0x0", "")
    code_bytes = bytes.fromhex(code[2:]) if has_code else b""

    impl_storage = None
    if has_code:
        impl_storage = storage_address(
            rpc_call(args.rpc, "eth_getStorageAt", [args.address, EIP1967_IMPLEMENTATION_SLOT, "latest"], args.timeout)
        )

    minimal_target = detect_minimal_proxy(code) if has_code else None
    report = {
        "address": args.address,
        "chain_id": chain_id,
        "latest_block": block_number,
        "has_code": has_code,
        "address_type": "contract" if has_code else "eoa_or_empty",
        "bytecode_bytes": len(code_bytes),
        "bytecode_sha256": hashlib.sha256(code_bytes).hexdigest() if has_code else None,
        "eip1967_implementation": impl_storage,
        "eip1167_minimal_proxy_target": minimal_target,
        "proxy_hint": bool(impl_storage or minimal_target),
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for key, value in report.items():
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
