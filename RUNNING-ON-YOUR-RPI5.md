# Running pq-bench-rpi5 on Your Own Raspberry Pi 5

This benchmark measures post-quantum KEMs, signatures, and TLS 1.3 handshakes
against the classical baseline Logos uses today (X25519 / Ed25519), so every
chart shows the **migration cost** of moving to PQ on validator-grade hardware.

There's no manual tuning: the benchmark **auto-calibrates the iteration count
per operation** to your Pi's speed, so results stay comparable across machines.

## Prerequisites

- **Raspberry Pi 5** (Cortex-A76, aarch64), ideally the 8GB model, with
  **active cooling** so it doesn't thermal-throttle mid-run.
- **Raspberry Pi OS / Debian 13 (trixie) or newer** — the benchmark pins
  OpenSSL to the **3.5.x LTS line** on every platform, and Debian 13's system
  `openssl` package is already 3.5.x with the PQC algorithms (ML-KEM / ML-DSA /
  SLH-DSA) compiled in, so **no OpenSSL source build is needed**. *(Status:
  verified from Debian packaging metadata — trixie ships `3.5.6-1~deb13u2` and
  its build rules disable none of the PQC algorithms — but not yet confirmed
  on a Pi by this project. Check with:)*

  ```sh
  openssl version                    # want 3.5.x
  openssl list -kem-algorithms | grep -i mlkem   # want ML-KEM entries
  ```

  If your OS ships an older OpenSSL, `./setup/setup.sh` falls back to building
  the pinned `openssl-3.5.7` from source automatically (adds ~15–30 min).
- **Rust toolchain — not needed yet.** A later stage adds a Rust harness
  (RustCrypto primitives + rustls TLS); when it lands, this guide will gain a
  `rustup` install step. Nothing to do today.
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
temperature. A full run currently takes **roughly 25–30 min on a Pi 5**: the
last published consolidated run recorded 1351 s (~22.5 min), and the candidate
list has since gained the four FIPS 205 SLH-DSA rows next to the four SPHINCS+
rows — hash-based signing dominates, so expect a few extra minutes (estimate,
not yet measured on a Pi). There are no iteration counts to set. Expect further
growth once the later stages add the RustCrypto, OpenSSL-native-TLS and rustls
measurement groups — this guide will state a measured figure when those land.

Output lands in `results/<hostname>-<timestamp>.json`, stamped with full
provenance (Pi model, RAM, kernel, governor, thermal trace, library versions)
and an `is_baseline_grade` flag.

## Step 4 — View results

The dashboard must be served over **HTTP** (opening `index.html` as a `file://`
URL blocks its JSON fetch — see `dashboard/README.md`):

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

- Hash-based signatures are measured in **both generations**: the standardised
  FIPS 205 SLH-DSA sets (`SLH_DSA_PURE_SHA2_*`, new rows) **and** the round-3
  `SPHINCS+-SHA2-*-simple` sets (the rows comparable to the earlier published
  baselines). They are different algorithms — compare like with like.
- Currently measures **liboqs** (C / assembly) implementations plus the
  oqs-provider TLS matrix; the pure-Rust second source (RustCrypto, rustls) and
  the OpenSSL-native TLS path are separate measurement groups arriving in later
  stages — the results schema already carries the `implementation` and `phase`
  fields for them.
- Userspace PMU cycle counts are usually unavailable, so the primary metric is
  **wall-clock time + ops/sec**.
- SNARK / STARK benchmarking is **out of scope** for this phase (`config.yaml`
  reserves a hook for it).
- The candidate list lives in `config.yaml` — use the exact liboqs algorithm
  names.
