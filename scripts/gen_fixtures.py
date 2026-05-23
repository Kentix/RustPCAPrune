#!/usr/bin/env python3
"""Generate synthetic parity fixtures under fixtures/. Requires scapy."""

from pathlib import Path

from scapy.all import Dot1Q, Ether, IP, IPv6, Raw, TCP, UDP, conf, wrpcap

# Avoid L2 neighbor resolution (no root / BPF required for wrpcap).
conf.verb = 0
conf.cache_neighbor = False
_L2 = lambda: Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
from scapy.layers.inet import IPOption_LSRR
from scapy.layers.inet6 import IPv6ExtHdrHopByHop
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TLS_APP = bytes([0x17, 0x03, 0x03, 0x01, 0xF4]) + b"X" * 40
TLS_HS = bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + b"H" * 20


def w(name: str, pkts: list) -> None:
    path = FIXTURES / name
    wrpcap(str(path), pkts)
    print(f"  {path.name} ({len(pkts)} pkts)")


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    print("writing fixtures/")

    base_tls = (
        _L2()
        / IP(dst="10.0.0.2", src="10.0.0.1")
        / TCP(dport=443, sport=45678)
        / Raw(load=TLS_APP)
    )
    w("synth-tls-443.pcap", [base_tls] * 5)

    w(
        "synth-tls-handshake-kept.pcap",
        [
            _L2() / IP()
            / TCP(dport=443, sport=1234)
            / Raw(load=TLS_HS)
        ]
        * 3,
    )

    w(
        "synth-non-tls-port-tls-shape.pcap",
        [
            _L2() / IP()
            / TCP(dport=8080, sport=1234)
            / Raw(load=TLS_APP)
        ]
        * 3,
    )

    w(
        "synth-ssh-banner-kept.pcap",
        [
            _L2() / IP()
            / TCP(dport=22, sport=1234)
            / Raw(load=b"SSH-2.0-OpenSSH\r\n" + b"\x00" * 30)
        ]
        * 2,
    )

    w(
        "synth-ssh-encrypted.pcap",
        [_L2() / IP() / TCP(dport=22, sport=1234) / Raw(load=b"\x00" * 40)] * 2,
    )

    w(
        "synth-udp-quic.pcap",
        [_L2() / IP() / UDP(dport=443, sport=1234) / Raw(load=b"\x00" * 40)] * 3,
    )

    w(
        "synth-udp-dns-kept.pcap",
        [_L2() / IP() / UDP(dport=53, sport=1234) / Raw(load=b"\x00" * 40)] * 2,
    )

    w(
        "synth-udp-ipsec.pcap",
        [_L2() / IP() / UDP(dport=500, sport=1234) / Raw(load=b"\x00" * 40)] * 2,
    )

    w(
        "synth-vlan-tls.pcap",
        [
            _L2()
            / Dot1Q(vlan=100)
            / IP()
            / TCP(dport=443, sport=20000)
            / Raw(load=TLS_APP)
        ]
        * 4,
    )

    w(
        "synth-qinq-tls.pcap",
        [
            _L2()
            / Dot1Q(vlan=100)
            / Dot1Q(vlan=200)
            / IP()
            / TCP(dport=443, sport=20001)
            / Raw(load=TLS_APP)
        ]
        * 4,
    )

    w(
        "synth-ipv6-tls.pcap",
        [
            _L2()
            / IPv6(dst="2001:db8::2", src="2001:db8::1")
            / TCP(dport=443, sport=30000)
            / Raw(load=TLS_APP)
        ]
        * 4,
    )

    w(
        "synth-ipv6-hbh-tls.pcap",
        [
            _L2()
            / IPv6()
            / IPv6ExtHdrHopByHop()
            / TCP(dport=443, sport=30001)
            / Raw(load=TLS_APP)
        ]
        * 4,
    )

    w(
        "synth-tcp-options-tls.pcap",
        [
            _L2() / IP()
            / TCP(
                dport=443,
                sport=40000,
                options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 8)],
            )
            / Raw(load=TLS_APP)
        ]
        * 4,
    )

    w(
        "synth-ipv4-options.pcap",
        [
            _L2()
            / IP(options=IPOption_LSRR(routers=["1.2.3.4"]))
            / TCP(dport=443, sport=12345)
            / Raw(load=TLS_APP)
        ]
        * 20,
    )

    w(
        "synth-mixed.pcap",
        [
            base_tls,
            _L2() / IP() / TCP(dport=443) / Raw(load=TLS_HS),
            _L2() / IP() / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n" + b"Z" * 30),
            _L2() / IP() / UDP(dport=53) / Raw(load=b"\x00" * 30),
            _L2() / IP() / UDP(dport=443) / Raw(load=b"\x00" * 30),
        ],
    )

    print("done.")


if __name__ == "__main__":
    main()
