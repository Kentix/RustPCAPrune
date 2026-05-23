#!/usr/bin/env python3
"""Slim a pcap using the reference Scapy implementation (pcap_slim_lib semantics)."""

from __future__ import annotations

import sys
from pathlib import Path

# Allow importing sibling project reference implementation
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "PCAP_External_Cleaner"))

from scapy.all import IP, IPv6, PcapReader, PcapWriter, Raw, TCP, UDP  # noqa: E402

from pcap_slim_lib import _maybe_truncate  # noqa: E402


def slim_file(src: Path, dst: Path) -> None:
    with PcapReader(str(src)) as reader, PcapWriter(str(dst), sync=True) as writer:
        for pkt in reader:
            writer.write(_maybe_truncate(pkt, IP, IPv6, TCP, UDP, Raw))


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <in.pcap> <out.pcap>", file=sys.stderr)
        return 2
    slim_file(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
