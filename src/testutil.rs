//! Shared test helpers for building synthetic frames and pcaps.

pub mod pcap_fixtures {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    const GHDR_LE: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
        0, 0x01, 0, 0, 0,
    ];

    const GHDR_BE: [u8; 24] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        0x01, 0, 0, 0,
    ];

    /// Write a minimal valid libpcap (LE) with `n` identical TLS-truncatable frames.
    pub fn write_minimal_pcap(path: &Path, n: u32) -> std::io::Result<()> {
        let frame = crate::testutil::eth_ipv4_tcp_frame(443, 12345, &[0x17; 30]);
        let frames: Vec<_> = (0..n).map(|_| frame.as_slice()).collect();
        write_pcap_records(path, &frames, None)
    }

    /// Big-endian libpcap with `n` identical frames.
    pub fn write_minimal_pcap_be(path: &Path, n: u32) -> std::io::Result<()> {
        let frame = crate::testutil::eth_ipv4_tcp_frame(443, 12345, &[0x17; 30]);
        let frames: Vec<_> = (0..n).map(|_| frame.as_slice()).collect();
        write_pcap_records_be(path, &frames, None)
    }

    /// Write LE pcap with optional per-packet `incl_len` overrides (defaults to frame.len()).
    pub fn write_pcap_records(
        path: &Path,
        frames: impl IntoIterator<Item = impl AsRef<[u8]>>,
        incl_lens: Option<&[usize]>,
    ) -> std::io::Result<()> {
        write_pcap_inner(path, &GHDR_LE, true, frames, incl_lens)
    }

    fn write_pcap_records_be(
        path: &Path,
        frames: impl IntoIterator<Item = impl AsRef<[u8]>>,
        incl_lens: Option<&[usize]>,
    ) -> std::io::Result<()> {
        write_pcap_inner(path, &GHDR_BE, false, frames, incl_lens)
    }

    fn write_pcap_inner(
        path: &Path,
        ghdr: &[u8; 24],
        le: bool,
        frames: impl IntoIterator<Item = impl AsRef<[u8]>>,
        incl_lens: Option<&[usize]>,
    ) -> std::io::Result<()> {
        let mut f = File::create(path)?;
        f.write_all(ghdr)?;
        for (i, frame) in frames.into_iter().enumerate() {
            let frame = frame.as_ref();
            let incl = incl_lens
                .and_then(|l| l.get(i).copied())
                .unwrap_or(frame.len());
            let incl = incl.min(frame.len());
            let mut rec = [0u8; 16];
            write_u32(&mut rec[8..12], incl as u32, le);
            write_u32(&mut rec[12..16], frame.len() as u32, le);
            f.write_all(&rec)?;
            f.write_all(&frame[..incl])?;
        }
        Ok(())
    }

    fn write_u32(buf: &mut [u8], v: u32, le: bool) {
        if le {
            buf.copy_from_slice(&v.to_le_bytes());
        } else {
            buf.copy_from_slice(&v.to_be_bytes());
        }
    }
}

/// Build Ethernet + IPv4 + TCP frame with payload.
pub fn eth_ipv4_tcp_frame(dport: u16, sport: u16, payload: &[u8]) -> Vec<u8> {
    let ip_hdr = 20usize;
    let tcp_hdr = 20usize;
    let ip_len = (ip_hdr + tcp_hdr + payload.len()) as u16;
    let total = 14 + ip_len as usize;
    let mut v = vec![0u8; total];
    v[12] = 0x08;
    v[13] = 0x00;
    v[14] = 0x45;
    v[16] = (ip_len >> 8) as u8;
    v[17] = (ip_len & 0xff) as u8;
    v[23] = 6;
    let tcp_off = 34;
    v[tcp_off] = (sport >> 8) as u8;
    v[tcp_off + 1] = (sport & 0xff) as u8;
    v[tcp_off + 2] = (dport >> 8) as u8;
    v[tcp_off + 3] = (dport & 0xff) as u8;
    v[tcp_off + 12] = 0x50;
    v[tcp_off + tcp_hdr..].copy_from_slice(payload);
    v
}

/// TCP with 12-byte options (data offset = 8 → 32-byte header).
pub fn eth_ipv4_tcp_frame_with_tcp_opts(dport: u16, sport: u16, payload: &[u8]) -> Vec<u8> {
    let ip_hdr = 20usize;
    let tcp_hdr = 32usize;
    let ip_len = (ip_hdr + tcp_hdr + payload.len()) as u16;
    let total = 14 + ip_len as usize;
    let mut v = vec![0u8; total];
    v[12] = 0x08;
    v[13] = 0x00;
    v[14] = 0x45;
    v[16] = (ip_len >> 8) as u8;
    v[17] = (ip_len & 0xff) as u8;
    v[23] = 6;
    let tcp_off = 34;
    v[tcp_off] = (sport >> 8) as u8;
    v[tcp_off + 1] = (sport & 0xff) as u8;
    v[tcp_off + 2] = (dport >> 8) as u8;
    v[tcp_off + 3] = (dport & 0xff) as u8;
    v[tcp_off + 12] = 0x80;
    v[tcp_off + tcp_hdr..].copy_from_slice(payload);
    v
}
