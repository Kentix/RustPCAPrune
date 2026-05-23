//! RFC 1071 Internet checksums for IPv4, TCP, and UDP.

/// Max TCP/UDP segment after slim: 32-byte TCP hdr + 24 payload (or 8 + 24 UDP).
const MAX_TRANSPORT_SEGMENT: usize = 64;

/// One's complement sum of 16-bit words, folded to 16 bits (not inverted).
pub fn checksum_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    finish(checksum_sum(data))
}

/// IPv4 header checksum (header only, checksum field zeroed).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

fn checksum_sum_pseudo_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, segment: &[u8]) -> u32 {
    let len = segment.len() as u16;
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(&src);
    ph[4..8].copy_from_slice(&dst);
    ph[9] = proto;
    ph[10] = (len >> 8) as u8;
    ph[11] = (len & 0xff) as u8;
    let mut sum = checksum_sum(&ph) + checksum_sum(segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn checksum_sum_pseudo_ipv6(src: [u8; 16], dst: [u8; 16], proto: u8, segment: &[u8]) -> u32 {
    let mut sum = checksum_sum(&src) + checksum_sum(&dst);
    sum += checksum_sum(&(segment.len() as u32).to_be_bytes());
    sum += u32::from(proto);
    sum += checksum_sum(segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

/// TCP/UDP checksum over pseudo-header + segment (stack buffer, no heap).
pub fn transport_checksum_ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    segment: &[u8],
) -> u16 {
    debug_assert!(segment.len() <= MAX_TRANSPORT_SEGMENT);
    finish(checksum_sum_pseudo_ipv4(src, dst, proto, segment))
}

pub fn transport_checksum_ipv6(
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    segment: &[u8],
) -> u16 {
    debug_assert!(segment.len() <= MAX_TRANSPORT_SEGMENT);
    finish(checksum_sum_pseudo_ipv6(src, dst, proto, segment))
}

/// Write UDP checksum; use 0xFFFF when computed checksum is zero.
pub fn udp_checksum_wire(sum: u16) -> u16 {
    if sum == 0 {
        0xffff
    } else {
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sum() {
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    #[test]
    fn ipv4_header_checksum_roundtrip() {
        let mut hdr = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let sum = ipv4_header_checksum(&hdr);
        hdr[10] = (sum >> 8) as u8;
        hdr[11] = (sum & 0xff) as u8;
        assert_ne!(sum, 0);
        assert_eq!(internet_checksum(&hdr), 0);
    }

    #[test]
    fn udp_checksum_wire_zero_becomes_ffff() {
        assert_eq!(udp_checksum_wire(0), 0xffff);
        assert_eq!(udp_checksum_wire(0x1234), 0x1234);
    }

    #[test]
    fn transport_ipv4_pseudo_nonzero() {
        let segment = [0u8; 8];
        let sum = transport_checksum_ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &segment);
        assert_ne!(sum, 0);
    }
}
