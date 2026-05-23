# pcap-slim algorithm — deterministic spec

A complete behavioural specification of what `admin-scripts/pcap-slim.py`
does to packets, suitable as a reference for re-implementation in a faster
language (Rust, Go, C++).

## Goal

Given a pcap file, produce a slim pcap that:
- Preserves every packet's existence, ordering, and timestamp
- Preserves all L2/L3/L4 headers byte-for-byte
- Preserves all *cleartext* application data (DNS, plain HTTP, SMTP, etc.)
- Preserves TLS *handshake* records (which contain SNI, certificates, JA3/JA3S
  fingerprintable data — these are unencrypted by design)
- Truncates only the encrypted application data of detectable encrypted
  protocols, replacing it with the first 24 bytes of that payload

## Per-packet decision tree

For each packet in arrival order:

1. **Locate IP layer.** Resolve the outermost IPv4 or IPv6 header.
   If neither is present (pure L2, ARP, etc.) → **keep packet unchanged**.

2. **Branch on L4 protocol.**

### 2a. TCP

Let `sport`, `dport` = TCP ports; `payload` = TCP payload bytes after the
TCP header (length = total IP length − IP header − TCP header).

If `len(payload) <= 24` → **keep unchanged**. (Nothing to gain from
truncating something already at or below the floor.)

Let `b0` = `payload[0]`.

Three decision cases:

  i. **TLS-port + non-handshake**:
     `(sport ∈ TLS_PORTS OR dport ∈ TLS_PORTS) AND b0 ∉ TLS_HANDSHAKE_BYTES`
     → **truncate** (this is TLS ApplicationData, Alert, etc. — encrypted)

  ii. **Non-TLS-port but TLS-shaped ApplicationData**:
      `(sport ∉ TLS_PORTS AND dport ∉ TLS_PORTS) AND b0 == TLS_APPLICATION_DATA`
      → **truncate** (TLS over a non-standard port, only the encrypted
      record type byte)

  iii. **SSH past banner**:
       `(sport ∈ SSH_PORTS OR dport ∈ SSH_PORTS) AND payload does not start with b"SSH-"`
       → **truncate** (SSH handshake banner is "SSH-..."; everything after
       is encrypted)

  iv. Otherwise → **keep unchanged**

### 2b. UDP

Let `sport`, `dport` = UDP ports; `payload` = UDP payload bytes.

If `len(payload) <= 24` → **keep unchanged**.

If `(sport ∈ QUIC_PORTS OR dport ∈ QUIC_PORTS) OR (sport ∈ IPSEC_PORTS OR dport ∈ IPSEC_PORTS)`
→ **truncate** (QUIC is encrypted from packet 1; IPsec ESP/IKE payloads are
encrypted).

Otherwise → **keep unchanged**.

### 2c. Neither TCP nor UDP

→ **keep unchanged** (ICMP, GRE, ESP-direct, OSPF, IGMP, etc.)

## Constants (must match exactly)

```
TRUNCATE_PAYLOAD_BYTES = 24

TLS_HANDSHAKE_BYTES  = {0x14, 0x15, 0x16, 0x18}
    # 0x14 ChangeCipherSpec  0x15 Alert  0x16 Handshake  0x18 Heartbeat
TLS_APPLICATION_DATA = 0x17

TLS_PORTS   = {443, 853, 465, 993, 995, 8443, 5061}
QUIC_PORTS  = {443}              # UDP
IPSEC_PORTS = {500, 4500}        # IKE / ESP-in-UDP
SSH_PORTS   = {22}
```

Rationale for the port sets:
- **TLS_PORTS**: HTTPS, DoT, SMTPS, IMAPS, POP3S, alt-HTTPS, SIP-TLS
- **QUIC_PORTS**: HTTP/3 over UDP/443 (overlap with TLS:443 is intentional;
  branch is decided by L4 protocol)
- **IPSEC_PORTS**: IKE (500), NAT-T ESP (4500)
- **SSH_PORTS**: SSH

## Truncation mechanics

When truncating a TCP packet:

1. Slice `payload[:24]`.
2. Replace the TCP payload with those 24 bytes.
3. **Invalidate the following header fields so the encoder recomputes
   them** (otherwise the resulting pcap will have wrong lengths and the
   IP/TCP checksums will fail for any tool that validates them):
   - IPv4: `len`, `chksum`
   - IPv6: `plen`
   - TCP: `chksum`

When truncating a UDP packet:

1. Slice `payload[:24]`.
2. Replace the UDP payload with those 24 bytes.
3. Invalidate:
   - IPv4: `len`, `chksum`
   - IPv6: `plen`
   - UDP: `len`, `chksum`

The encoder must recompute all four fields from the new packet structure
before serializing. (Scapy does this implicitly because `del pkt.field`
marks the field as "compute on build". A faster implementation must do
the same arithmetic explicitly.)

## File-level coordination

For each input pcap file at path `<src>`:

1. Compute marker path: `<dir>/.slim_markers/<basename>` (where `<dir>` is
   `<src>`'s parent directory).
2. **If the marker file exists, skip the file entirely** — it has already
   been slimmed. This is the idempotency mechanism: re-runs are no-ops.
3. Otherwise, write the slim output to `<src>.tmp` (same directory).
4. After writing, re-open the .tmp file and count packets. If the count
   does not equal the input packet count, **abort and delete the .tmp**
   (the slim was corrupted; original is untouched).
5. If the count matches, `rename(<src>.tmp, <src>)` (POSIX atomic
   rename — replaces the original in one syscall).
6. Create the marker file (0 bytes is fine; existence is the signal).
   - Owner: `sensor:sensor`
   - Mode: `0644` (file), `0755` (`.slim_markers/` directory)

This sequence guarantees:
- **Atomicity**: a crash before step 5 leaves the original intact + a
  detectable .tmp orphan
- **Idempotency**: a second run skips at step 2
- **Verifiability**: a corrupt slim aborts at step 4 with original intact

## Orphan-tmp cleanup

On startup, any `*.pcap.tmp` in the processed directory whose mtime is
older than 5 minutes (300 seconds) should be deleted. These are leftover
fragments from prior aborted runs. The 5-minute threshold avoids racing
a currently-in-progress slim from another worker.

## Multi-worker safety

Multiple workers may run against the same directory simultaneously. The
contract:

- Each worker processes files atomically via .tmp + rename
- The marker-file check before slimming prevents two workers from
  duplicating work on the same file
- The marker-file write after rename should be the **last** write
- Workers should select files by listing the directory, filtering out
  any already-markered files, and (optionally) sorting by mtime so that
  oldest files are processed first

This does NOT require file locking — the marker-existence check + the
atomic rename are sufficient. A small race window exists where two
workers may both decide to slim the same file before either creates a
marker; in that case both produce identical output (deterministic
slim) and the second rename simply replaces the first's result, which is
harmless.

## Performance targets

The Python+scapy reference implementation achieves:
- ~7 MB/s single-worker
- ~28 MB/s with 4 parallel workers (ProcessPoolExecutor)
- ~18–25% retained size on production traffic (TLS-heavy)
- ~1330 seconds wall time per ~0.9 GB file at 1 worker (observed on one
  test run)

A native re-implementation should target:
- 50–200 MB/s single-threaded (limited mainly by pcap I/O + checksum
  recomputation)
- Linear scaling to disk bandwidth with `N` parallel workers
- Same byte-identical output as the reference (deterministic)

## I/O format

Input and output are standard libpcap files (magic `0xa1b2c3d4` or
`0xd4c3b2a1`, depending on endianness). The per-packet record header
(`pcap_pkthdr`: `ts_sec`, `ts_usec`, `incl_len`, `orig_len`) must be
preserved exactly, except `incl_len` must be updated to match the
truncated packet's new size. `orig_len` (the on-wire size before any
earlier snaplen truncation) should be left unchanged — the slim file
still reports what was originally on the wire.

The pcap global header (snaplen, network type, etc.) must be copied
verbatim from input to output.

**Parity testing note:** `scapy.utils.PcapWriter` hardcodes `snaplen = 65535` in
output regardless of input. pcap-slim preserves the input snaplen. When comparing
to Scapy reference output, only bytes 16–19 of the global header may differ;
compare packet bodies from offset 24 onward (or use Rust output hashes in
`fixtures/expected_hashes.json` as the regression source of truth).

## Input format handling

| Magic (first 4 bytes) | Format | Behaviour |
|---|---|---|
| `a1 b2 c3 d4` | libpcap native endian | Process normally |
| `d4 c3 b2 a1` | libpcap swapped endian | Process normally |
| `0a 0d 0d 0a` | pcapng | Error: exit 1, file unchanged. Message recommends `editcap -F pcap` conversion. |
| (other) | Unknown | Error: exit 1, file unchanged |

## Production scheduling (`--age-minutes`)

When run against a directory (`--dir`), an optional **age filter** skips any
`.pcap` whose modification time is newer than `now − N minutes`. This lets
downstream indexers (e.g. Arkime offline) finish reading the raw capture before
in-place slimming rewrites encrypted payloads. Marker files are checked after
the age filter. The flag does not apply to `--single`.

## I/O mode (`--dir`)

For directory batch runs, input may be read via **memory-mapped files** or
buffered `read()`. By default, mmap is used for up to two parallel workers; with
more workers, buffered I/O is selected automatically to reduce cold-cache
page-fault contention on large files. Operators may force either mode with
`--mmap` or `--no-mmap`.

## Edge cases (must handle)

1. **VLAN-tagged packets (802.1Q)**: the IP layer lookup must traverse
   through the VLAN tag. Scapy does this automatically via
   `pkt.getlayer(IP)`. Native code must explicitly check for
   `ethtype == 0x8100` and skip the 4-byte VLAN header before reading IP.

2. **IPv4 with options**: IP header length (IHL field) may be > 5
   (20 bytes). Use IHL × 4 to find payload offset.

3. **TCP with options**: TCP data offset field, multiply by 4.

4. **Fragmented IP packets**: leave fragments alone (don't attempt to
   reassemble). Encrypted protocols rarely fragment; this is acceptable
   loss.

5. **Packets where claimed length exceeds actual captured bytes**: the
   pcap `incl_len` is the captured length. Trust it; never read past it.
   If a truncated packet's TCP/UDP header is itself incomplete (rare,
   caused by snaplen), keep the packet unchanged.

6. **Non-Ethernet pcap link types**: the reference implementation
   assumes DLT_EN10MB (Ethernet). Other link types (Linux SLL, Wi-Fi,
   loopback) need their own L2 parsing. For Malcolm's use case, only
   Ethernet matters.

## What this algorithm does NOT do

- No DPI or content inspection (e.g., does not extract HTTP headers
  from cleartext HTTP — those flow through unchanged because
  port 80 is not in any encrypted set)
- No re-encryption, no anonymization of IPs or MACs
- No flow reassembly
- No per-connection state tracking (each packet is decided in isolation
  on port + first-byte heuristics)

The lack of per-flow state is what makes this trivially parallelizable
and what allows a native re-implementation to be embarrassingly fast.
