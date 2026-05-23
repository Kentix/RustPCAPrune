#!/usr/bin/env python3
"""Generate fixtures/synth-ipv4-options.pcap for TCP checksum regression."""

from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap
from scapy.layers.inet import IPOption_LSRR

def main() -> None:
    out = Path(__file__).resolve().parents[1] / "fixtures" / "synth-ipv4-options.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    pkts = []
    for _ in range(20):
        pkt = (
            Ether()
            / IP(
                options=IPOption_LSRR(routers=["1.2.3.4"]),
                proto=6,
            )
            / TCP(dport=443, sport=12345)
            / Raw(load=bytes([0x17, 0x03, 0x03, 0x01, 0xF4]) + b"X" * 40)
        )
        pkts.append(pkt)
    wrpcap(str(out), pkts)
    print(f"wrote {out} ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
