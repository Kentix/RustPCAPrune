//! Per-packet slim decision tree (must match pcap-slim-algorithm.md).

use crate::parse::{L4Proto, ParsedFrame};

pub const TRUNCATE_PAYLOAD_BYTES: usize = 24;

pub const TLS_HANDSHAKE_BYTES: &[u8] = &[0x14, 0x15, 0x16, 0x18];
pub const TLS_APPLICATION_DATA: u8 = 0x17;

pub const TLS_PORTS: &[u16] = &[443, 853, 465, 993, 995, 8443, 5061];
pub const QUIC_PORTS: &[u16] = &[443];
pub const IPSEC_PORTS: &[u16] = &[500, 4500];
pub const SSH_PORTS: &[u16] = &[22];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Keep,
    Truncate,
}

pub fn port_in_set(port: u16, set: &[u16]) -> bool {
    set.contains(&port)
}

/// Decide whether to truncate L4 payload for a parsed frame.
pub fn decide_action(parsed: &ParsedFrame) -> Action {
    if !parsed.is_ipv6 {
        let ip = parsed.ip_start;
        let flags_frag = u16::from_be_bytes([parsed.frame[ip + 6], parsed.frame[ip + 7]]);
        if flags_frag & 0x3fff != 0 {
            return Action::Keep;
        }
    }

    let Some(l4) = parsed.l4 else {
        return Action::Keep;
    };

    match l4.proto {
        L4Proto::Tcp => decide_tcp(l4.sport, l4.dport, parsed.payload()),
        L4Proto::Udp => decide_udp(l4.sport, l4.dport, parsed.payload()),
    }
}

fn decide_tcp(sport: u16, dport: u16, payload: &[u8]) -> Action {
    if payload.is_empty() || payload.len() <= TRUNCATE_PAYLOAD_BYTES {
        return Action::Keep;
    }
    let b0 = payload[0];
    let is_tls_port = port_in_set(sport, TLS_PORTS) || port_in_set(dport, TLS_PORTS);
    let is_handshake = TLS_HANDSHAKE_BYTES.contains(&b0);

    if is_tls_port && !is_handshake {
        return Action::Truncate;
    }
    if !is_tls_port && b0 == TLS_APPLICATION_DATA {
        return Action::Truncate;
    }
    if (port_in_set(sport, SSH_PORTS) || port_in_set(dport, SSH_PORTS))
        && !payload.starts_with(b"SSH-")
    {
        return Action::Truncate;
    }
    Action::Keep
}

fn decide_udp(sport: u16, dport: u16, payload: &[u8]) -> Action {
    if payload.is_empty() || payload.len() <= TRUNCATE_PAYLOAD_BYTES {
        return Action::Keep;
    }
    if port_in_set(sport, QUIC_PORTS)
        || port_in_set(dport, QUIC_PORTS)
        || port_in_set(sport, IPSEC_PORTS)
        || port_in_set(dport, IPSEC_PORTS)
    {
        return Action::Truncate;
    }
    Action::Keep
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame;

    // Minimal IPv4/TCP frame builder helpers for inline test frames.
    #[test]
    fn tcp_tls_app_data_truncates() {
        // Ethernet + IPv4(20) + TCP(20) + 30 bytes payload starting with 0x17
        let mut frame = build_eth_ipv4_tcp(443, 12345, &[0x17; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Truncate);
        frame = build_eth_ipv4_tcp(12345, 443, &[0x17; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Truncate);
    }

    #[test]
    fn tcp_tls_handshake_kept() {
        let frame = build_eth_ipv4_tcp(443, 12345, &[0x16; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Keep);
    }

    #[test]
    fn tcp_tls_other_handshake_bytes_kept() {
        for &b0 in &[0x14u8, 0x15, 0x18] {
            let frame = build_eth_ipv4_tcp(443, 12345, &[b0; 30]);
            assert_eq!(
                decide_action(&parse_frame(&frame).unwrap()),
                Action::Keep,
                "b0=0x{b0:02x}"
            );
        }
    }

    #[test]
    fn ipv4_fragment_kept() {
        let mut frame = build_eth_ipv4_tcp(443, 12345, &[0x17; 30]);
        frame[20] |= 0x20;
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Keep);
    }

    #[test]
    fn tcp_non_tls_port_app_data_truncates() {
        let frame = build_eth_ipv4_tcp(8080, 12345, &[0x17; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Truncate);
    }

    #[test]
    fn tcp_short_payload_kept() {
        let frame = build_eth_ipv4_tcp(443, 12345, &[0x17; 20]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Keep);
    }

    #[test]
    fn ssh_banner_kept() {
        let mut p = b"SSH-2.0-test\r\n".to_vec();
        p.resize(30, 0);
        let frame = build_eth_ipv4_tcp(22, 12345, &p);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Keep);
    }

    #[test]
    fn ssh_encrypted_truncates() {
        let frame = build_eth_ipv4_tcp(22, 12345, &[0x00; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Truncate);
    }

    #[test]
    fn udp_quic_truncates() {
        let frame = build_eth_ipv4_udp(443, 12345, &[0; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Truncate);
    }

    #[test]
    fn udp_dns_kept() {
        let frame = build_eth_ipv4_udp(53, 12345, &[0; 30]);
        assert_eq!(decide_action(&parse_frame(&frame).unwrap()), Action::Keep);
    }

    fn build_eth_ipv4_tcp(dport: u16, sport: u16, payload: &[u8]) -> Vec<u8> {
        let ip_hdr = 20usize;
        let tcp_hdr = 20usize;
        let total = 14 + ip_hdr + tcp_hdr + payload.len();
        let ip_len = (ip_hdr + tcp_hdr + payload.len()) as u16;
        let mut v = vec![0u8; total];
        v[12] = 0x08;
        v[13] = 0x00; // IPv4
        v[14] = 0x45;
        v[16] = (ip_len >> 8) as u8;
        v[17] = (ip_len & 0xff) as u8;
        v[23] = 6; // TCP
        let ip_off = 14;
        let tcp_off = ip_off + ip_hdr;
        v[tcp_off] = (sport >> 8) as u8;
        v[tcp_off + 1] = (sport & 0xff) as u8;
        v[tcp_off + 2] = (dport >> 8) as u8;
        v[tcp_off + 3] = (dport & 0xff) as u8;
        v[tcp_off + 12] = 0x50; // data offset 5
        v[tcp_off + tcp_hdr..].copy_from_slice(payload);
        v
    }

    fn build_eth_ipv4_udp(dport: u16, sport: u16, payload: &[u8]) -> Vec<u8> {
        let ip_hdr = 20usize;
        let udp_hdr = 8usize;
        let total = 14 + ip_hdr + udp_hdr + payload.len();
        let ip_len = (ip_hdr + udp_hdr + payload.len()) as u16;
        let udp_len = (udp_hdr + payload.len()) as u16;
        let mut v = vec![0u8; total];
        v[12] = 0x08;
        v[13] = 0x00;
        v[14] = 0x45;
        v[16] = (ip_len >> 8) as u8;
        v[17] = (ip_len & 0xff) as u8;
        v[23] = 17; // UDP
        let udp_off = 14 + ip_hdr;
        v[udp_off] = (sport >> 8) as u8;
        v[udp_off + 1] = (sport & 0xff) as u8;
        v[udp_off + 2] = (dport >> 8) as u8;
        v[udp_off + 3] = (dport & 0xff) as u8;
        v[udp_off + 4] = (udp_len >> 8) as u8;
        v[udp_off + 5] = (udp_len & 0xff) as u8;
        v[udp_off + udp_hdr..].copy_from_slice(payload);
        v
    }
}
