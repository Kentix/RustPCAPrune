# RustPCAPrune

**RustPCAPrune** is a native Rust implementation of the [pcap-slim algorithm](pcap-slim-algorithm.md): stream through a libpcap file, preserve every packet's timestamp and headers, and truncate only encrypted L4 payloads to the first 24 bytes.

The crate and binary are named `pcap-slim` to match the algorithm and keep CLI invocations identical to the Python reference predecessor.

## Build

```bash
cargo build --release
```

Binary: `target/release/pcap-slim`

The default build enables **mmap** input (`--features mmap`). Disable with `cargo build --release --no-default-features`.

## Usage

### Production batch (systemd timer on Malcolm / Hedgehog)

Wait for downstream indexers (e.g. Arkime offline) to finish, then slim in place:

```bash
pcap-slim --dir /home/sensor/Malcolm/pcap/processed \
          --age-minutes 15 \
          --workers 2 \
          --output json
```

- **`--age-minutes`**: only files whose mtime is at least N minutes old (`--dir` only).
- **`--workers 2`**: recommended for typical sensor deployments; mmap is used automatically for ≤2 workers.
- For **`--workers 4`**, buffered `read()` is used automatically (avoids cold-cache mmap page-fault contention). Force mmap with `--mmap` if you accept the trade-off.

### One-shot file

```bash
pcap-slim --single /path/to/capture.pcap
pcap-slim --single /path/to/large.pcap --mmap    # optional mmap for single file
```

### Dry run / analysis only

```bash
pcap-slim --dir /path --age-minutes 15 --dry-run
pcap-slim --single capture.pcap --check-only
pcap-slim --dir /path --check-only --output json
```

### Throttled (shared production hosts)

```bash
pcap-slim --dir /path --age-minutes 15 --workers 2 \
          --max-io-mbps 50 \
          --cpu-backoff-above 70
```

### Structured output (monitoring)

```bash
pcap-slim --dir /path --age-minutes 15 --output json | jq .
```

### CLI flags (reference)

| Flag | Purpose |
|------|---------|
| `--dir PATH` | Slim all pending `.pcap` files in directory (in place) |
| `--single PATH` | Slim one file in place |
| `--workers N` | Parallel files (`--dir` only; does not split one pcap) |
| `--age-minutes N` | Skip files newer than N minutes (`--dir` only) |
| `--dry-run` | List eligible files, no writes |
| `--check-only` | Analyze only; no writes or markers |
| `--output human\|json` | Per-file report format |
| `--max-io-mbps N` | Shared read+write throughput cap |
| `--max-cpu-percent N` | Process CPU cap (1–100) |
| `--cpu-backoff-above N` | Reduce target when host load is high |
| `--cpu-backoff-strength F` | Backoff aggressiveness (0.0–1.0, default 0.5) |
| `--mmap` | Force mmap reads |
| `--no-mmap` | Force buffered reads (overrides auto selection) |

### I/O mode (`--dir`)

| Workers | Default I/O |
|---------|-------------|
| 1–2 | mmap |
| 3+ | buffered `read()` (override with `--mmap`) |

### Coordination contract

For each `capture.pcap`:

1. Skip if `.slim_markers/capture.pcap` exists
2. Write `capture.pcap.tmp`, verify packet count matches slim pass
3. Atomically rename tmp over original
4. Create marker file (`sensor:sensor` when that user exists; else calling user)

On startup, delete stale `*.pcap.tmp` files older than 5 minutes in `--dir`.

## Performance

Production budgets (cold cache) are documented in `benches/budgets.txt`.

```bash
cargo run --release --bin budget_check
```

Measure locally:

```bash
cargo build --release
time target/release/pcap-slim --single large.pcap
```

Release profile: thin LTO, `codegen-units = 1`, stripped binary.

## Tests

```bash
python3 scripts/gen_fixtures.py          # synthetic fixtures
python3 scripts/gen_expected_hashes.py   # after: cargo build --release
cargo test
```

- **`fixtures/expected.json`**: per-file `analyze` stats (Rust source of truth).
- **`fixtures/expected_hashes.json`**: SHA-256 of Rust slim output per fixture (not Python/scapy).
- **Scapy parity** (optional): `cargo test --test golden --test golden_fixtures -- --ignored`

### Parity notes

- **snaplen**: Rust preserves the input global header verbatim (spec). Scapy writes `snaplen = 65535`. Body bytes match when comparing from offset 24; golden hashes use full Rust output files.
- **pcapng**: Rejected with exit 1 and a clear message; file unchanged.
- **IPv4 LSRR/SSRR**: TCP/UDP pseudo-header uses source-route address (matches Scapy).

## Algorithm reference

See [pcap-slim-algorithm.md](pcap-slim-algorithm.md). Python reference: `../PCAP_External_Cleaner/pcap_slim_lib.py`.

