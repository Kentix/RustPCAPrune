//! Streaming libpcap read/write with preserved timestamps and orig_len.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
#[cfg(feature = "mmap")]
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::limit::ResourceLimits;
use crate::packet::{process_packet, PacketOutcome};

const PCAP_HDR_LEN: usize = 24;
const PCAP_REC_HDR_LEN: usize = 16;
const READ_BUF_CAP: usize = 4 * 1024 * 1024;
const WRITE_BATCH_CAP: usize = 512 * 1024;
const CPU_TICK_INTERVAL: u64 = 64;
const SKIP_BUF_CAP: usize = 65536;

const MAGIC_LE: u32 = 0xa1b2_c3d4;
const MAGIC_BE: u32 = 0xd4c3_b2a1;

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid or unsupported pcap: {0}")]
    Invalid(&'static str),
    #[error(
        "'{path}' is pcapng format (not supported). Convert with: editcap -F pcap '{path}' '<path>.pcap'"
    )]
    Pcapng { path: String },
}

#[derive(Clone, Copy)]
struct Endian {
    le: bool,
}

impl Endian {
    fn read_u32(&self, buf: &[u8]) -> u32 {
        if self.le {
            u32::from_le_bytes(buf.try_into().unwrap())
        } else {
            u32::from_be_bytes(buf.try_into().unwrap())
        }
    }

    fn write_u32(&self, buf: &mut [u8], v: u32) {
        if self.le {
            buf.copy_from_slice(&v.to_le_bytes());
        } else {
            buf.copy_from_slice(&v.to_be_bytes());
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SlimStats {
    pub in_pkts: u64,
    pub truncated: u64,
    pub kept: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
}

/// Projected output file size after slimming (global header + record headers + frames).
pub fn projected_file_size(global_hdr_len: u64, per_packet_out: u64) -> u64 {
    global_hdr_len + per_packet_out
}

fn account_io(limits: Option<&Arc<ResourceLimits>>, bytes: u64) {
    if let Some(lim) = limits {
        lim.acquire_io(bytes);
    }
}

fn flush_limits(limits: Option<&Arc<ResourceLimits>>) {
    if let Some(lim) = limits {
        lim.flush_io();
    }
}

fn maybe_cpu_tick(limits: Option<&Arc<ResourceLimits>>, pkt_index: u64) {
    if let Some(lim) = limits {
        if pkt_index > 0 && pkt_index % CPU_TICK_INTERVAL == 0 {
            lim.cpu_tick();
        }
    }
}

/// Validate the file begins with legacy libpcap magic (not pcapng).
pub fn validate_pcap_magic(path: &Path) -> Result<(), PcapError> {
    let mut hdr = [0u8; 4];
    let mut f = File::open(path)?;
    match f.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(PcapError::Invalid("file too short for pcap header"));
        }
        Err(e) => return Err(e.into()),
    }
    check_magic_bytes(&hdr, path)
}

fn check_magic_bytes(magic: &[u8; 4], path: &Path) -> Result<(), PcapError> {
    if *magic == PCAPNG_MAGIC {
        return Err(PcapError::Pcapng {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn open_pcap_reader(path: &Path, use_mmap: bool) -> Result<Box<dyn Read>, PcapError> {
    let file = File::open(path)?;
    #[cfg(feature = "mmap")]
    if use_mmap {
        let map = unsafe { memmap2::Mmap::map(&file)? };
        return Ok(Box::new(Cursor::new(map)));
    }
    let _ = use_mmap;
    Ok(Box::new(BufReader::with_capacity(READ_BUF_CAP, file)))
}

fn read_global_header(
    reader: &mut dyn Read,
    path: &Path,
) -> Result<(Endian, [u8; PCAP_HDR_LEN]), PcapError> {
    let mut ghdr = [0u8; PCAP_HDR_LEN];
    match reader.read_exact(&mut ghdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(PcapError::Invalid("file too short for pcap header"));
        }
        Err(e) => return Err(e.into()),
    }
    check_magic_bytes(ghdr[0..4].try_into().unwrap(), path)?;
    let endian = detect_endian(&ghdr)?;
    Ok((endian, ghdr))
}

fn read_frame_into(reader: &mut dyn Read, frame_buf: &mut Vec<u8>, incl_len: usize) -> io::Result<()> {
    if frame_buf.len() < incl_len {
        frame_buf.reserve(incl_len - frame_buf.len());
    }
    unsafe {
        frame_buf.set_len(incl_len);
    }
    if incl_len > 0 {
        reader.read_exact(&mut frame_buf[..incl_len])?;
    }
    Ok(())
}

struct WriteBatch<'a, W: Write + ?Sized> {
    buf: Vec<u8>,
    writer: &'a mut W,
    limits: Option<&'a Arc<ResourceLimits>>,
}

impl<'a, W: Write + ?Sized> WriteBatch<'a, W> {
    fn new(writer: &'a mut W, limits: Option<&'a Arc<ResourceLimits>>) -> Self {
        Self {
            buf: Vec::with_capacity(WRITE_BATCH_CAP.min(64 * 1024)),
            writer,
            limits,
        }
    }

    fn write_record(&mut self, rec_hdr: &[u8; PCAP_REC_HDR_LEN], frame: &[u8]) -> io::Result<()> {
        let need = PCAP_REC_HDR_LEN + frame.len();
        if !self.buf.is_empty() && self.buf.len() + need > WRITE_BATCH_CAP {
            self.flush()?;
        }
        self.buf.extend_from_slice(rec_hdr);
        self.buf.extend_from_slice(frame);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let n = self.buf.len() as u64;
        self.writer.write_all(&self.buf)?;
        account_io(self.limits, n);
        self.buf.clear();
        Ok(())
    }
}

fn skip_packet_body(reader: &mut dyn Read, incl_len: usize, skip_buf: &mut [u8]) -> io::Result<()> {
    let mut remaining = incl_len;
    while remaining > 0 {
        let chunk = remaining.min(skip_buf.len());
        reader.read_exact(&mut skip_buf[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}

/// Stream-slim `src` into `writer`, copying the global header verbatim.
pub fn slim_pcap_to_writer(
    src: &Path,
    writer: &mut impl Write,
    stats: &mut SlimStats,
    limits: Option<&Arc<ResourceLimits>>,
) -> Result<(), PcapError> {
    slim_pcap_to_writer_with_options(src, writer, stats, limits, false)
}

/// Stream-slim with optional mmap input (`feature = "mmap"`).
pub fn slim_pcap_to_writer_with_options(
    src: &Path,
    writer: &mut impl Write,
    stats: &mut SlimStats,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<(), PcapError> {
    stats.in_bytes = std::fs::metadata(src)?.len();
    let mut reader = open_pcap_reader(src, use_mmap)?;
    let (endian, ghdr) = read_global_header(reader.as_mut(), src)?;
    account_io(limits, PCAP_HDR_LEN as u64);

    writer.write_all(&ghdr)?;
    account_io(limits, PCAP_HDR_LEN as u64);

    let mut rec_hdr = [0u8; PCAP_REC_HDR_LEN];
    let mut frame_buf = Vec::with_capacity(2048);
    let mut write_batch = WriteBatch::new(writer, limits);

    loop {
        match reader.read_exact(&mut rec_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        account_io(limits, PCAP_REC_HDR_LEN as u64);

        let ts_sec = endian.read_u32(&rec_hdr[0..4]);
        let ts_usec = endian.read_u32(&rec_hdr[4..8]);
        let incl_len = endian.read_u32(&rec_hdr[8..12]) as usize;
        let orig_len = endian.read_u32(&rec_hdr[12..16]);

        read_frame_into(reader.as_mut(), &mut frame_buf, incl_len)?;
        account_io(limits, incl_len as u64);

        stats.in_pkts += 1;
        let (outcome, was_truncated) = process_packet(&frame_buf);

        let frame_out: &[u8] = match &outcome {
            PacketOutcome::Keep => &frame_buf,
            PacketOutcome::Truncated(buf) => buf.as_slice(),
        };

        if was_truncated {
            stats.truncated += 1;
        } else {
            stats.kept += 1;
        }

        let new_incl = frame_out.len() as u32;
        endian.write_u32(&mut rec_hdr[0..4], ts_sec);
        endian.write_u32(&mut rec_hdr[4..8], ts_usec);
        endian.write_u32(&mut rec_hdr[8..12], new_incl);
        endian.write_u32(&mut rec_hdr[12..16], orig_len);

        write_batch.write_record(&rec_hdr, frame_out)?;

        maybe_cpu_tick(limits, stats.in_pkts);
    }

    write_batch.flush()?;
    flush_limits(limits);
    Ok(())
}

/// Slim `src` to `dst` path (full file).
pub fn slim_pcap(
    src: &Path,
    dst: &Path,
    limits: Option<&Arc<ResourceLimits>>,
) -> Result<SlimStats, PcapError> {
    slim_pcap_with_options(src, dst, limits, false)
}

/// Slim with optional mmap input (`feature = "mmap"`).
pub fn slim_pcap_with_options(
    src: &Path,
    dst: &Path,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<SlimStats, PcapError> {
    let outfile = File::create(dst)?;
    let mut writer = BufWriter::with_capacity(READ_BUF_CAP, outfile);
    let mut stats = SlimStats::default();
    slim_pcap_to_writer_with_options(src, &mut writer, &mut stats, limits, use_mmap)?;
    writer.flush()?;
    writer.get_ref().sync_data()?;
    flush_limits(limits);
    stats.out_bytes = std::fs::metadata(dst)?.len();
    Ok(stats)
}

/// Count packets in a pcap file.
pub fn count_packets(
    path: &Path,
    limits: Option<&Arc<ResourceLimits>>,
) -> Result<u64, PcapError> {
    count_packets_with_options(path, limits, false)
}

pub fn count_packets_with_options(
    path: &Path,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<u64, PcapError> {
    let mut reader = open_pcap_reader(path, use_mmap)?;
    let (endian, _) = read_global_header(reader.as_mut(), path)?;
    account_io(limits, PCAP_HDR_LEN as u64);

    let mut rec_hdr = [0u8; PCAP_REC_HDR_LEN];
    let mut skip_buf = [0u8; SKIP_BUF_CAP];
    let mut count = 0u64;
    loop {
        match reader.read_exact(&mut rec_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        account_io(limits, PCAP_REC_HDR_LEN as u64);
        let incl_len = endian.read_u32(&rec_hdr[8..12]) as usize;
        skip_packet_body(reader.as_mut(), incl_len, &mut skip_buf)?;
        account_io(limits, incl_len as u64);
        count += 1;
        maybe_cpu_tick(limits, count);
    }
    flush_limits(limits);
    Ok(count)
}

/// Read a pcap and compute what slim would do, without writing output.
pub fn analyze_pcap(
    path: &Path,
    limits: Option<&Arc<ResourceLimits>>,
) -> Result<SlimStats, PcapError> {
    analyze_pcap_with_options(path, limits, false)
}

pub fn analyze_pcap_with_options(
    path: &Path,
    limits: Option<&Arc<ResourceLimits>>,
    use_mmap: bool,
) -> Result<SlimStats, PcapError> {
    let mut stats = SlimStats::default();
    stats.in_bytes = std::fs::metadata(path)?.len();

    let mut reader = open_pcap_reader(path, use_mmap)?;
    let (endian, _) = read_global_header(reader.as_mut(), path)?;
    account_io(limits, PCAP_HDR_LEN as u64);

    let mut rec_hdr = [0u8; PCAP_REC_HDR_LEN];
    let mut frame_buf = Vec::with_capacity(2048);
    let mut body_bytes = 0u64;

    loop {
        match reader.read_exact(&mut rec_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        account_io(limits, PCAP_REC_HDR_LEN as u64);

        let incl_len = endian.read_u32(&rec_hdr[8..12]) as usize;
        read_frame_into(reader.as_mut(), &mut frame_buf, incl_len)?;
        account_io(limits, incl_len as u64);

        stats.in_pkts += 1;
        let (outcome, was_truncated) = process_packet(&frame_buf);
        let out_len = match &outcome {
            PacketOutcome::Keep => frame_buf.len(),
            PacketOutcome::Truncated(buf) => buf.len(),
        };
        if was_truncated {
            stats.truncated += 1;
        } else {
            stats.kept += 1;
        }
        body_bytes += PCAP_REC_HDR_LEN as u64 + out_len as u64;

        maybe_cpu_tick(limits, stats.in_pkts);
    }

    flush_limits(limits);
    stats.out_bytes = projected_file_size(PCAP_HDR_LEN as u64, body_bytes);
    Ok(stats)
}

fn detect_endian(ghdr: &[u8]) -> Result<Endian, PcapError> {
    let magic = u32::from_le_bytes(ghdr[0..4].try_into().unwrap());
    match magic {
        MAGIC_LE => Ok(Endian { le: true }),
        MAGIC_BE => Ok(Endian { le: false }),
        _ => {
            let magic_be = u32::from_be_bytes(ghdr[0..4].try_into().unwrap());
            if magic_be == MAGIC_LE {
                Ok(Endian { le: true })
            } else if magic_be == MAGIC_BE {
                Ok(Endian { le: false })
            } else {
                Err(PcapError::Invalid("unknown pcap magic"))
            }
        }
    }
}
