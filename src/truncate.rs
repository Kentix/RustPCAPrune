//! In-place L4 payload truncation and header/checksum updates.

use crate::checksum::{
    internet_checksum, transport_checksum_ipv4, transport_checksum_ipv6, udp_checksum_wire,
};
use crate::parse::{L4Info, L4Proto, ParsedFrame};
use crate::policy::TRUNCATE_PAYLOAD_BYTES;

fn apply_truncate_fields(
    buf: &mut Vec<u8>,
    ip_start: usize,
    ip_header_len: usize,
    is_ipv6: bool,
    l4: L4Info,
    payload_len: usize,
) -> bool {
    if payload_len <= TRUNCATE_PAYLOAD_BYTES {
        return false;
    }

    let l4_header_start = l4.header_start;
    let l4_header_len = l4.header_len;
    let payload_start = l4.payload_start;

    let new_payload_end = payload_start + TRUNCATE_PAYLOAD_BYTES;
    if new_payload_end >= buf.len() {
        return false;
    }
    buf.truncate(new_payload_end);

    let new_ip_total = buf.len() - ip_start;
    if is_ipv6 {
        let plen = (new_ip_total - ip_header_len) as u16;
        buf[ip_start + 4] = (plen >> 8) as u8;
        buf[ip_start + 5] = (plen & 0xff) as u8;
    } else {
        buf[ip_start + 2] = (new_ip_total >> 8) as u8;
        buf[ip_start + 3] = (new_ip_total & 0xff) as u8;
        update_ipv4_header_checksum(buf, ip_start, ip_header_len);
    }

    match l4.proto {
        L4Proto::Tcp => {
            update_tcp_checksum(buf, ip_start, ip_header_len, is_ipv6, l4_header_start);
        }
        L4Proto::Udp => {
            let udp_len = (l4_header_len + TRUNCATE_PAYLOAD_BYTES) as u16;
            buf[l4_header_start + 4] = (udp_len >> 8) as u8;
            buf[l4_header_start + 5] = (udp_len & 0xff) as u8;
            update_udp_checksum(
                buf,
                ip_start,
                ip_header_len,
                is_ipv6,
                l4_header_start,
                l4_header_len + TRUNCATE_PAYLOAD_BYTES,
            );
        }
    }
    true
}

/// Truncate using an already-parsed frame (no second parse).
pub fn apply_truncate_on_parsed(buf: &mut Vec<u8>, parsed: &ParsedFrame<'_>) -> bool {
    let (ip_start, ip_header_len, is_ipv6, l4, payload_len) = {
        let Some(l4) = parsed.l4 else {
            return false;
        };
        (
            parsed.ip_start,
            parsed.ip_header_len,
            parsed.is_ipv6,
            l4,
            parsed.payload().len(),
        )
    };
    apply_truncate_fields(buf, ip_start, ip_header_len, is_ipv6, l4, payload_len)
}

/// Truncate encrypted payload in `buf`. Returns true if the frame was shortened.
pub fn apply_truncate(buf: &mut Vec<u8>) -> bool {
    let (ip_start, ip_header_len, is_ipv6, l4, payload_len) = {
        let Ok(parsed) = crate::parse::parse_frame(buf) else {
            return false;
        };
        let Some(l4) = parsed.l4 else {
            return false;
        };
        (
            parsed.ip_start,
            parsed.ip_header_len,
            parsed.is_ipv6,
            l4,
            parsed.payload().len(),
        )
    };
    apply_truncate_fields(buf, ip_start, ip_header_len, is_ipv6, l4, payload_len)
}

/// Legacy helper for tests: clone + truncate.
pub fn process_frame(frame: &[u8], truncate: bool) -> (Vec<u8>, bool) {
    if !truncate {
        return (frame.to_vec(), false);
    }
    let mut buf = frame.to_vec();
    if apply_truncate(&mut buf) {
        (buf, true)
    } else {
        (frame.to_vec(), false)
    }
}

fn update_ipv4_header_checksum(buf: &mut [u8], ip_start: usize, ip_header_len: usize) {
    buf[ip_start + 10] = 0;
    buf[ip_start + 11] = 0;
    let sum = internet_checksum(&buf[ip_start..ip_start + ip_header_len]);
    buf[ip_start + 10] = (sum >> 8) as u8;
    buf[ip_start + 11] = (sum & 0xff) as u8;
}

fn update_tcp_checksum(
    buf: &mut [u8],
    ip_start: usize,
    _ip_header_len: usize,
    is_ipv6: bool,
    tcp_start: usize,
) {
    buf[tcp_start + 16] = 0;
    buf[tcp_start + 17] = 0;
    let segment = &buf[tcp_start..];

    let sum = if is_ipv6 {
        let src = read_ip6(buf, ip_start + 8);
        let dst = read_ip6(buf, ip_start + 24);
        transport_checksum_ipv6(src, dst, 6, segment)
    } else {
        let src = read_ip4(buf, ip_start + 12);
        let dst = crate::parse::ipv4_pseudo_dst(buf, ip_start, _ip_header_len);
        transport_checksum_ipv4(src, dst, 6, segment)
    };
    buf[tcp_start + 16] = (sum >> 8) as u8;
    buf[tcp_start + 17] = (sum & 0xff) as u8;
}

fn update_udp_checksum(
    buf: &mut [u8],
    ip_start: usize,
    ip_header_len: usize,
    is_ipv6: bool,
    udp_start: usize,
    udp_len: usize,
) {
    buf[udp_start + 6] = 0;
    buf[udp_start + 7] = 0;
    let segment = &buf[udp_start..udp_start + udp_len];

    let sum = if is_ipv6 {
        let src = read_ip6(buf, ip_start + 8);
        let dst = read_ip6(buf, ip_start + 24);
        transport_checksum_ipv6(src, dst, 17, segment)
    } else {
        let src = read_ip4(buf, ip_start + 12);
        let dst = crate::parse::ipv4_pseudo_dst(buf, ip_start, ip_header_len);
        transport_checksum_ipv4(src, dst, 17, segment)
    };
    let wire = udp_checksum_wire(sum);
    buf[udp_start + 6] = (wire >> 8) as u8;
    buf[udp_start + 7] = (wire & 0xff) as u8;
}

fn read_ip4(buf: &[u8], off: usize) -> [u8; 4] {
    [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]
}

fn read_ip6(buf: &[u8], off: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&buf[off..off + 16]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame;
    use crate::policy::TRUNCATE_PAYLOAD_BYTES;
    use crate::testutil::eth_ipv4_tcp_frame;

    #[test]
    fn truncate_tls_payload_to_24_bytes() {
        let frame = eth_ipv4_tcp_frame(443, 12345, &[0x17; 40]);
        let before = frame.len();
        let parsed = parse_frame(&frame).unwrap();
        let mut buf = frame.clone();
        assert!(apply_truncate_on_parsed(&mut buf, &parsed));
        assert_eq!(buf.len(), before - 16);
        let out_parsed = parse_frame(&buf).unwrap();
        assert_eq!(out_parsed.payload().len(), TRUNCATE_PAYLOAD_BYTES);
    }

    #[test]
    fn truncate_updates_ipv4_total_length() {
        let frame = eth_ipv4_tcp_frame(443, 1, &[0x17; 30]);
        let parsed = parse_frame(&frame).unwrap();
        let mut buf = frame.clone();
        assert!(apply_truncate_on_parsed(&mut buf, &parsed));
        let ip_len = u16::from_be_bytes([buf[16], buf[17]]) as usize;
        assert_eq!(ip_len + 14, buf.len());
    }

    #[test]
    fn truncate_sets_tcp_checksum() {
        let frame = eth_ipv4_tcp_frame(443, 1, &[0x17; 30]);
        let parsed = parse_frame(&frame).unwrap();
        let mut buf = frame.clone();
        assert!(apply_truncate_on_parsed(&mut buf, &parsed));
        let csum = u16::from_be_bytes([buf[50], buf[51]]);
        assert_ne!(csum, 0);
    }
}
