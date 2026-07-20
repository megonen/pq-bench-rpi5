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
  openssl list -kem-algorithms | grep -i mlkem     # want ML-KEM entries
  # the native TLS matrix additionally needs (unverified on a Pi so far —
  # expected present in any stock 3.5.x build):
  openssl list -tls-groups | tr ':' '\n' | grep -i mlkem   # MLKEM512/768/1024 + hybrids
  openssl list -tls-signature-algorithms | tr ':' '\n' | grep -i mldsa  # mldsa44/65/87
  ```

  If the native MLKEM TLS groups are missing, `run.sh` skips the
  `openssl-native` TLS matrix with a warning and the oqs-provider matrix still
  runs.

  If your OS ships an older OpenSSL, `./setup/setup.sh` falls back to building
  the pinned `openssl-3.5.7` from source automatically (adds ~15–30 min).
- **Rust toolchain** — needed for the `rustcrypto` measurement group (pure-Rust
  ML-KEM/ML-DSA/SLH-DSA plus X25519/Ed25519 anchors). Install stable Rust via
  rustup:

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  . "$HOME/.cargo/env"
  cargo --version    # any recent stable is fine
  ```

  (Debian 13 also packages `rustup` — `sudo apt install rustup && rustup default
  stable` should be equivalent, but that path has not been verified by this
  project.) The Rust toolchain now covers TWO measurement groups: the
  `rustcrypto` primitives (`bench/rust`) and the `rustls-awslc` TLS matrix
  (`bench/rust-tls`). The latter compiles the AWS-LC C library on first build
  (several extra minutes on a Pi; needs `cmake`, which `setup.sh deps` already
  installs — unverified on a Pi so far). **Optional:** if cargo is absent,
  `./run.sh` skips both Rust groups gracefully and records the reasons in the
  results JSON — the rest of the benchmark is unaffected.
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
sudo env "PATH=$PATH" ./run.sh
```

`sudo` is needed to set the performance governor, pin cores, and read the
temperature. **The `env "PATH=$PATH"` matters**: rustup installs cargo under
`~/.cargo/bin`, which root's default PATH does not include — plain
`sudo ./run.sh` would silently skip both Rust measurement groups (with a
recorded warning, but you'd lose two of the four groups).

A full run now covers **all four measurement groups** (liboqs primitives,
RustCrypto primitives, aws-lc-rs pricing rows, and the three-stack TLS phase
matrix: openssl-native / oqs-provider / rustls-awslc, ~60 cells at 1000
handshakes each). On the Apple M3 the full run measured 36 min; on a Pi 5
expect **roughly 50–70 min** (estimate, not yet measured on a Pi — the
hash-based signature rows and the SPHINCS+ TLS cells dominate), plus the
one-time first-run Rust builds (see prerequisites). There are no iteration
counts to set.

To exercise the whole pipeline end-to-end first without a publishable-length
run, use smoke mode — same coverage (all four groups, every TLS stack), one
repetition per op and 50 handshakes per TLS cell:

```sh
sudo env "PATH=$PATH" ./run.sh --smoke
```

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
- Measures **liboqs** (C / assembly) implementations, the **RustCrypto
  pure-Rust second source** (`implementation: rustcrypto` rows — same
  methodology, hedged signing like liboqs; Falcon/McEliece/FrodoKEM have no
  mature pure-Rust implementation and stay absent there), the **aws-lc-rs
  pricing rows**, and the **three-stack TLS phase matrix** (`openssl-native`,
  `oqs-provider`, `rustls-awslc`) — see README for what each covers and the
  caveats that apply.
- Rust-vs-C gaps are partly **optimisation-path artefacts**, not pure
  implementation quality: liboqs has hand-written aarch64 assembly for ML-KEM,
  the Rust crates are portable Rust. The results JSON records both sides'
  compiled code paths (`toolchain.liboqs_opt_defines` / `toolchain.rust`).
- Userspace PMU cycle counts are usually unavailable, so the primary metric is
  **wall-clock time + ops/sec**.
- SNARK / STARK benchmarking is **out of scope** for this phase (`config.yaml`
  reserves a hook for it).
- The candidate list lives in `config.yaml` — use the exact liboqs algorithm
  names.
