#!/usr/bin/env python3
"""Regenerate fixtures/expected_hashes.json from Rust slim output (source of truth)."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
BIN = ROOT / "target" / "release" / "pcap-slim"


def main() -> None:
    if not BIN.exists():
        print("build release binary first: cargo build --release", file=sys.stderr)
        sys.exit(1)

    table: dict[str, str] = {}
    for pcap in sorted(FIXTURES.glob("*.pcap")):
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / pcap.name
            shutil.copy2(pcap, dst)
            subprocess.run([str(BIN), "--single", str(dst)], check=True)
            digest = hashlib.sha256(dst.read_bytes()).hexdigest()
            table[pcap.name] = digest
            print(f"  {pcap.name}  {digest[:16]}…")

    out = FIXTURES / "expected_hashes.json"
    out.write_text(json.dumps(table, indent=2) + "\n")
    print(f"wrote {out} ({len(table)} entries)")


if __name__ == "__main__":
    main()
