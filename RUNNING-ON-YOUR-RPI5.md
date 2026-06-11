# Running pq-bench-rpi5 on Your Own Raspberry Pi 5

This benchmark measures post-quantum KEMs, signatures, and TLS 1.3 handshakes
against the classical baseline Logos uses today (X25519 / Ed25519), so every
chart shows the **migration cost** of moving to PQ on validator-grade hardware.

There's no manual tuning: the benchmark **auto-calibrates the iteration count
per operation** to your Pi's speed, so results stay comparable across machines.

## Prerequisites

- **Raspberry Pi 5** (Cortex-A76, aarch64), ideally the 8GB model, with
  **active cooling** so it doesn't thermal-throttle mid-run.
- **Raspberry Pi OS / Debian Trixie or newer** — system OpenSSL 3.5+ so PQ TLS
  works without a source build.
- **Internet access** and **sudo**.

## Step 1 — Clone (public repo, no auth)

```sh
git clone <REPO_URL>
cd pq-bench-rpi5
```

## Step 2 — Build the toolchain

```sh
./setup/setup.sh all
```

Takes 5–15 min: installs dependencies and builds liboqs + oqs-provider. Run it
inside `tmux` so it survives an SSH disconnect.

## Step 3 — Run

```sh
sudo ./run.sh
```

`sudo` is needed to set the performance governor, pin cores, and read the
temperature. The run takes ~4–5 min, with no iteration counts to set.

Output lands in `results/<hostname>-<timestamp>.json`, stamped with full
provenance (Pi model, RAM, kernel, governor, thermal trace, library versions)
and an `is_baseline_grade` flag.

## Step 4 — View results

```sh
cd dashboard
python3 -m http.server 8765
# then open http://<pi-ip>:8765
```

The charts show KEM, signature, and TLS results with the classical X25519 /
Ed25519 baseline drawn as a reference line.

## Step 5 — Contribute (optional)

Share your `results/*.json` (open a PR or send it over). To merge results from
multiple machines:

```sh
python3 analyze/merge.py results/*.json -o dashboard/data/merged.json
```

The dashboard then shows every Pi side by side.

## What the results tell you

PQ is not so much *slower* as *bigger*. Lattice schemes (ML-KEM, ML-DSA) run
close to classical in speed but have much larger keys and signatures, while the
hash-based SLH-DSA (SPHINCS+) is an outlier in both signing time and signature
size. On TLS, the classical baseline fits in a single packet, while PQ and
hybrid handshakes grow past it and fragment.

## Notes and limitations

- Measures **liboqs** (C / assembly) implementations — a pure-Rust backend is a
  separate, optional axis.
- Userspace PMU cycle counts are usually unavailable, so the primary metric is
  **wall-clock time + ops/sec**.
- SNARK / STARK benchmarking is **out of scope** for this phase (`config.yaml`
  reserves a hook for it).
- The candidate list lives in `config.yaml` — use the exact liboqs algorithm
  names.
