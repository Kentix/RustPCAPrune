//! Ethernet (802.1Q) → IPv4/IPv6 → TCP/UDP offset parsing for DLT_EN10MB.

use thiserror::Error;

const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_IPV4: u16 = 0x0800;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// IPv4 option types (low 5 bits of option byte).
const IP_OPT_EOL: u8 = 0;
const IP_OPT_LSRR: u8 = 3;
const IP_OPT_SSRR: u8 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy)]
pub struct L4Info {
    pub proto: L4Proto,
    pub sport: u16,
    pub dport: u16,
    pub header_start: usize,
    pub header_len: usize,
    pub payload_start: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ParsedFrame<'a> {
    pub frame: &'a [u8],
    pub ip_start: usize,
    pub ip_header_len: usize,
    pub is_ipv6: bool,
    pub l4: Option<L4Info>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("frame too short")]
    TooShort,
}

impl<'a> ParsedFrame<'a> {
    pub fn payload(&self) -> &'a [u8] {
        let Some(l4) = self.l4 else {
            return &[];
        };
        let end = self.frame.len().min(l4.payload_start + self.payload_len());
        if l4.payload_start >= end {
            return &[];
        }
        &self.frame[l4.payload_start..end]
    }

    fn payload_len(&self) -> usize {
        let Some(l4) = self.l4 else {
            return 0;
        };
        let ip_total = if self.is_ipv6 {
            let plen = u16::from_be_bytes([
                self.frame[self.ip_start + 4],
                self.frame[self.ip_start + 5],
            ]) as usize;
            self.ip_header_len + plen
        } else {
            u16::from_be_bytes([
                self.frame[self.ip_start + 2],
                self.frame[self.ip_start + 3],
            ]) as usize
        };
        let l4_total = ip_total.saturating_sub(self.ip_header_len);
        let l4_hdr = l4.header_len;
        l4_total.saturating_sub(l4_hdr)
    }
}

/// IPv4 destination for TCP/UDP pseudo-header (matches scapy `in4_pseudoheader` for LSRR/SSRR).
pub fn ipv4_pseudo_dst(buf: &[u8], ip_start: usize, ip_header_len: usize) -> [u8; 4] {
    let default = [
        buf[ip_start + 16],
        buf[ip_start + 17],
        buf[ip_start + 18],
        buf[ip_start + 19],
    ];
    if ip_header_len <= 20 {
        return default;
    }
    let mut i = ip_start + 20;
    let end = ip_start + ip_header_len;
    while i < end {
        let kind = buf[i];
        if kind == IP_OPT_EOL {
            break;
        }
        if i + 1 >= end {
            break;
        }
        let opt_len = buf[i + 1] as usize;
        if opt_len < 2 || i + opt_len > end {
            break;
        }
        let ty = kind & 0x1f;
        if ty == IP_OPT_LSRR || ty == IP_OPT_SSRR {
            let data_start = i + 3;
            let data_end = i + opt_len;
            if data_end >= data_start + 4 {
                let last = data_end - 4;
                return [buf[last], buf[last + 1], buf[last + 2], buf[last + 3]];
            }
        }
        if opt_len == 0 {
            break;
        }
        i += opt_len;
    }
    default
}

/// Walk 802.1Q tag stack; returns inner ethertype and L3 start offset.
fn l2_ethertype_and_l3_start(frame: &[u8]) -> Option<(u16, usize)> {
    if frame.len() < 14 {
        return None;
    }
    let mut off = 12usize;
    loop {
        if off + 2 > frame.len() {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
        if ethertype != ETHERTYPE_VLAN {
            return Some((ethertype, off + 2));
        }
        if off + 4 > frame.len() {
            return None;
        }
        off += 4;
    }
}

/// Fast path: untagged Ethernet, IPv4 IHL=5, no fragments, standard TCP (20 B) or UDP (8 B).
fn try_parse_ipv4_plain(frame: &[u8]) -> Option<ParsedFrame<'_>> {
    if frame.len() < 54 {
        return None;
    }
    if frame[12] != 0x08 || frame[13] != 0x00 {
        return None;
    }
    let ip = 14usize;
    if frame[ip] != 0x45 {
        return None;
    }
    let flags = u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]);
    if flags & 0x3fff != 0 {
        return None;
    }
    let ip_total = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]) as usize;
    if frame.len() < ip + ip_total {
        return None;
    }
    let proto = frame[ip + 9];
    let l4_start = ip + 20;
    let l4_in_ip = ip_total.saturating_sub(20);

    let l4 = match proto {
        IP_PROTO_TCP => {
            if l4_in_ip < 20 || frame.len() < l4_start + 20 {
                return None;
            }
            if frame[l4_start + 12] >> 4 != 5 {
                return None;
            }
            let sport = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
            let dport = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
            Some(L4Info {
                proto: L4Proto::Tcp,
                sport,
                dport,
                header_start: l4_start,
                header_len: 20,
                payload_start: l4_start + 20,
            })
        }
        IP_PROTO_UDP => {
            if l4_in_ip < 8 || frame.len() < l4_start + 8 {
                return None;
            }
            let sport = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
            let dport = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
            Some(L4Info {
                proto: L4Proto::Udp,
                sport,
                dport,
                header_start: l4_start,
                header_len: 8,
                payload_start: l4_start + 8,
            })
        }
        _ => None,
    };

    Some(ParsedFrame {
        frame,
        ip_start: ip,
        ip_header_len: 20,
        is_ipv6: false,
        l4,
    })
}

/// Parse L2–L4 offsets from an Ethernet frame. Returns `None` for L4 if IP/L4 headers are incomplete.
pub fn parse_frame(frame: &[u8]) -> Result<ParsedFrame<'_>, ParseError> {
    if frame.len() < 14 {
        return Err(ParseError::TooShort);
    }

    if let Some(parsed) = try_parse_ipv4_plain(frame) {
        return Ok(parsed);
    }

    let Some((ethertype, l3_start)) = l2_ethertype_and_l3_start(frame) else {
        return Ok(ParsedFrame {
            frame,
            ip_start: 0,
            ip_header_len: 0,
            is_ipv6: false,
            l4: None,
        });
    };

    if ethertype == ETHERTYPE_IPV4 {
        return parse_ipv4(frame, l3_start);
    }
    if ethertype == ETHERTYPE_IPV6 {
        return parse_ipv6(frame, l3_start);
    }

    Ok(ParsedFrame {
        frame,
        ip_start: 0,
        ip_header_len: 0,
        is_ipv6: false,
        l4: None,
    })
}

fn parse_ipv4(frame: &[u8], ip_start: usize) -> Result<ParsedFrame<'_>, ParseError> {
    if frame.len() < ip_start + 20 {
        return Ok(ParsedFrame {
            frame,
            ip_start,
            ip_header_len: 0,
            is_ipv6: false,
            l4: None,
        });
    }
    let version_ihl = frame[ip_start];
    if version_ihl >> 4 != 4 {
        return Ok(ParsedFrame {
            frame,
            ip_start,
            ip_header_len: 0,
            is_ipv6: false,
            l4: None,
        });
    }
    let ip_header_len = ((version_ihl & 0x0f) as usize) * 4;
    if frame.len() < ip_start + ip_header_len {
        return Ok(ParsedFrame {
            frame,
            ip_start,
            ip_header_len,
            is_ipv6: false,
            l4: None,
        });
    }

    let proto = frame[ip_start + 9];
    let ip_total = u16::from_be_bytes([frame[ip_start + 2], frame[ip_start + 3]]) as usize;
    let l4_start = ip_start + ip_header_len;
    let l4_in_ip = ip_total.saturating_sub(ip_header_len);

    let l4 = match proto {
        IP_PROTO_TCP => parse_tcp(frame, l4_start, l4_in_ip),
        IP_PROTO_UDP => parse_udp(frame, l4_start, l4_in_ip),
        _ => None,
    };

    Ok(ParsedFrame {
        frame,
        ip_start,
        ip_header_len,
        is_ipv6: false,
        l4,
    })
}

/// IPv6 extension header next-header values we skip to reach TCP/UDP.
const IP6_HOP_BY_HOP: u8 = 0;
const IP6_ROUTING: u8 = 43;
const IP6_FRAGMENT: u8 = 44;
const IP6_ESP: u8 = 50;
const IP6_AH: u8 = 51;
const IP6_DEST_OPTS: u8 = 60;
const IP6_NO_NEXT: u8 = 59;

fn parse_ipv6(frame: &[u8], ip_start: usize) -> Result<ParsedFrame<'_>, ParseError> {
    const IP6_HDR: usize = 40;
    if frame.len() < ip_start + IP6_HDR {
        return Ok(ParsedFrame {
            frame,
            ip_start,
            ip_header_len: IP6_HDR,
            is_ipv6: true,
            l4: None,
        });
    }
    if frame[ip_start] >> 4 != 6 {
        return Ok(ParsedFrame {
            frame,
            ip_start,
            ip_header_len: IP6_HDR,
            is_ipv6: true,
            l4: None,
        });
    }

    let plen = u16::from_be_bytes([frame[ip_start + 4], frame[ip_start + 5]]) as usize;
    let payload_end = (ip_start + IP6_HDR + plen).min(frame.len());
    let mut next = frame[ip_start + 6];
    let mut off = ip_start + IP6_HDR;

    let l4 = loop {
        if off >= payload_end {
            break None;
        }
        match next {
            IP_PROTO_TCP => break parse_tcp(frame, off, payload_end - off),
            IP_PROTO_UDP => break parse_udp(frame, off, payload_end - off),
            IP6_NO_NEXT => break None,
            IP6_ESP => break None,
            IP6_HOP_BY_HOP | IP6_ROUTING | IP6_FRAGMENT | IP6_DEST_OPTS => {
                if off + 2 > payload_end {
                    break None;
                }
                let ext_len = (frame[off + 1] as usize + 1) * 8;
                if ext_len < 8 || off + ext_len > payload_end {
                    break None;
                }
                next = frame[off];
                off += ext_len;
            }
            IP6_AH => {
                if off + 2 > payload_end {
                    break None;
                }
                let payload_len = frame[off + 1] as usize;
                let ext_len = (payload_len + 2) * 4;
                if off + ext_len > payload_end {
                    break None;
                }
                next = frame[off];
                off += ext_len;
            }
            _ => break None,
        }
    };

    Ok(ParsedFrame {
        frame,
        ip_start,
        ip_header_len: IP6_HDR,
        is_ipv6: true,
        l4,
    })
}

fn parse_tcp(frame: &[u8], l4_start: usize, l4_len: usize) -> Option<L4Info> {
    if frame.len() < l4_start + 20 || l4_len < 20 {
        return None;
    }
    let data_offset = ((frame[l4_start + 12] >> 4) as usize) * 4;
    if data_offset < 20 || frame.len() < l4_start + data_offset {
        return None;
    }
    if l4_len < data_offset {
        return None;
    }
    let sport = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
    let dport = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
    Some(L4Info {
        proto: L4Proto::Tcp,
        sport,
        dport,
        header_start: l4_start,
        header_len: data_offset,
        payload_start: l4_start + data_offset,
    })
}

fn parse_udp(frame: &[u8], l4_start: usize, l4_len: usize) -> Option<L4Info> {
    const UDP_HDR: usize = 8;
    if frame.len() < l4_start + UDP_HDR || l4_len < UDP_HDR {
        return None;
    }
    let sport = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
    let dport = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
    Some(L4Info {
        proto: L4Proto::Udp,
        sport,
        dport,
        header_start: l4_start,
        header_len: UDP_HDR,
        payload_start: l4_start + UDP_HDR,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qinq_ipv4_tcp() {
        let ip_hdr = 20usize;
        let tcp_hdr = 20usize;
        let payload = 8usize;
        let ip_len = ip_hdr + tcp_hdr + payload;
        let total = 14 + 8 + ip_len;
        let mut frame = vec![0u8; total];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[16] = 0x81;
        frame[17] = 0x00;
        frame[20] = 0x08;
        frame[21] = 0x00;
        let ip = 22;
        frame[ip] = 0x45;
        frame[ip + 2] = (ip_len >> 8) as u8;
        frame[ip + 3] = (ip_len & 0xff) as u8;
        frame[ip + 9] = 6;
        frame[ip + ip_hdr + 12] = 0x50;
        let parsed = parse_frame(&frame).unwrap();
        assert!(parsed.l4.is_some());
        assert_eq!(parsed.ip_start, 22);
    }

    #[test]
    fn vlan_ipv4_tcp() {
        let ip_hdr = 20usize;
        let tcp_hdr = 20usize;
        let payload = 10usize;
        let ip_len = ip_hdr + tcp_hdr + payload;
        let total = 14 + 4 + ip_len;
        let mut frame = vec![0u8; total];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[16] = 0x08;
        frame[17] = 0x00;
        let ip = 18;
        frame[ip] = 0x45;
        frame[ip + 2] = (ip_len >> 8) as u8;
        frame[ip + 3] = (ip_len & 0xff) as u8;
        frame[ip + 9] = 6;
        let tcp = ip + ip_hdr;
        frame[tcp + 12] = 0x50;
        let parsed = parse_frame(&frame).unwrap();
        assert!(parsed.l4.is_some());
        assert_eq!(parsed.ip_start, 18);
    }

    #[test]
    fn ipv4_ssrr_pseudo_dst() {
        let mut frame = vec![0u8; 86];
        frame[14] = 0x47;
        frame[16] = 0x00;
        frame[17] = 0x48;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[127, 0, 0, 1]);
        frame[30..34].copy_from_slice(&[127, 0, 0, 1]);
        frame[34] = 0x89;
        frame[35] = 0x07;
        frame[36] = 0x04;
        frame[37..41].copy_from_slice(&[5, 6, 7, 8]);
        let dst = ipv4_pseudo_dst(&frame, 14, 28);
        assert_eq!(dst, [5, 6, 7, 8]);
    }

    #[test]
    fn ipv4_lsrr_pseudo_dst() {
        // LSRR to 1.2.3.4, IP dst 127.0.0.1
        let mut frame = vec![0u8; 86];
        frame[14] = 0x47;
        frame[16] = 0x00;
        frame[17] = 0x48;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[127, 0, 0, 1]);
        frame[30..34].copy_from_slice(&[127, 0, 0, 1]);
        frame[34] = 0x83;
        frame[35] = 0x07;
        frame[36] = 0x04;
        frame[37..41].copy_from_slice(&[1, 2, 3, 4]);
        let dst = ipv4_pseudo_dst(&frame, 14, 28);
        assert_eq!(dst, [1, 2, 3, 4]);
    }
}
