# pqc-bench

A reproducible, general-purpose **post-quantum cryptography benchmark**
(formerly `pq-bench-rpi5`) whose baseline **reference platform** is the
**Raspberry Pi 5** (Broadcom BCM2712, Cortex-A76,
aarch64). Anyone can run it on their own Pi 5 and the results aggregate and
compare apples-to-apples.

**Framing — migration cost.** How much does moving from the cryptography Logos
uses *today* (X25519 key exchange + Ed25519 signatures) to PQ candidates cost on
validator-grade hardware? Every chart draws that classical baseline as the
reference line, so the PQ "tax" is always visible.

Hooks are left for a later SNARK/STARK phase (see `config.yaml`); it is not
implemented yet.

---

## What gets measured

The benchmark targets **four measurement groups**, all landing in the same
self-describing results JSON and distinguished by a per-row `implementation`
field:

1. **liboqs — KEM + signatures** *(implemented)*: ML-KEM, Classic McEliece,
   FrodoKEM, ML-DSA, Falcon, SLH-DSA, plus the classical X25519/Ed25519
   baselines via OpenSSL EVP (`implementation: liboqs` / `openssl`).
2. **RustCrypto — KEM + signatures** *(implemented — `bench/rust`)*: pure-Rust
   implementations as an independent second source
   (`implementation: rustcrypto`), measured by a Rust harness (`pqb-rust`)
   that deliberately replicates `bench_pq.c`'s clock
   (`clock_gettime(CLOCK_MONOTONIC)` via libc), auto-calibration, and
   median/MAD statistics so the two groups are methodologically comparable.
   Crates (pinned exactly; `Cargo.lock` committed; all pre-1.0 and
   **unaudited** — fine for benchmarking): `ml-kem 0.3.2`, `ml-dsa 0.1.1`,
   `slh-dsa 0.2.0-rc.5`, plus `x25519-dalek 3.0.0` / `ed25519-dalek 3.0.0`
   for the in-family classical anchors. Signing is **hedged**, matching
   liboqs. Coverage: ML-KEM 512/768/1024, ML-DSA 44/65/87, SLH-DSA SHA2
   128f/128s/192f/256f, X25519, Ed25519. Rust signature rows carry **two
   verify shapes**: `verify` (decode public key from wire bytes + verify —
   the call shape of both `OQS_SIG_verify` and a TLS handshake) and
   `verify_cached_key` (pre-parsed key object, expansion amortised — the
   long-lived-peer pattern); their difference is the pk parse/expansion cost.
   Totals use `verify`. **Not covered** — Falcon, Classic
   McEliece and FrodoKEM have no mature pure-Rust implementation; those cells
   stay genuinely absent rather than being filled by an FFI wrapper (pqcrypto,
   liboqs-rust, aws-lc-rs), which would not be an independent source. The
   dependency tree is verified free of liboqs/PQClean/C-FFI. Requires
   cargo/rustc; if absent the group is skipped and the reason recorded in the
   results.
3. **TLS 1.3 handshakes by migration phase** *(implemented — two stacks)*:
   - `implementation: openssl-native` — OpenSSL ≥ 3.5's **own** PQC, the
     production-relevant path. The harness loads no provider for these rows
     and **asserts at runtime that no OQS provider is active**. Matrix:
     baseline (X25519+Ed25519), phase0 (X25519MLKEM768, SecP256r1MLKEM768 and
     pure MLKEM512/768/1024, each + Ed25519 — the harvest-now-decrypt-later
     configuration), phase2 (X25519MLKEM768 and the pure groups ×
     ML-DSA-44/65/87, with natively generated ML-DSA certificates).
   - `implementation: oqs-provider` — the full experimental-provider matrix,
     kept in full: its ML-DSA cells deliberately overlap the native matrix
     (same protocol + algorithms under two stacks isolates provider overhead),
     and its Falcon and SLH-DSA (`sphincssha2128fsimple`) cells exist **only**
     here — native OpenSSL can issue SLH-DSA certificates but cannot negotiate
     SLH-DSA in TLS 1.3 (the IETF codepoints are still draft), so that row
     being provider-only is itself a finding.
4. **rustls + aws-lc-rs TLS 1.3 handshakes** *(implemented — `bench/rust-tls`)*:
   the Rust TLS stack (`implementation: rustls-awslc`), same phase structure
   and same in-memory methodology (`pqb-rust-tls` mirrors `bench_tls.c`: same
   clock, same fixed connections+warmup loop, same statistics and
   bytes-on-wire/ClientHello accounting). Coverage — measured: X25519,
   X25519MLKEM768, SecP256r1MLKEM768, pure MLKEM768/MLKEM1024, against
   Ed25519 (baseline/phase0) and ML-DSA-44/65/87 (phase2, using the natively
   generated certificates). Recorded as `enabled:false` rows, not hidden:
   rustls 0.23 has **no MLKEM512** group, and **SLH-DSA is absent from
   rustls/aws-lc-rs entirely** — so across both production stacks SLH-DSA in
   TLS 1.3 exists only in the experimental oqs-provider. **Unstable-feature
   caveat**: the ML-DSA rows ride `rustls-post-quantum/aws-lc-rs-unstable`
   (aws-lc-rs's `unstable` ML-DSA API) and carry `unstable_features: true`
   in the row itself. **Two-variables caveat**: rustls-vs-OpenSSL compares
   two protocol implementations AND two crypto backends (aws-lc-rs vs
   OpenSSL native) at once — the variables are not separable from these
   numbers, and this is not a language comparison. Unlike `bench/rust`, this
   group makes no pure-Rust claim (aws-lc-rs wraps the AWS-LC C library).
   To price these handshakes' primitive sums correctly, the run also measures
   **aws-lc-rs pricing rows** (`implementation: aws-lc-rs`: ML-KEM-768/1024,
   ML-DSA-44/65/87, X25519, secp256r1, Ed25519, same bench_pq methodology) —
   explicitly the primitives these handshakes execute, NOT an independent
   implementation; Stage 3's exclusion of FFI wrappers from the pure-Rust
   group stands. Sums are priced strictly per-stack: C-stack cells from
   liboqs/openssl rows, rustls cells from aws-lc-rs rows, never across.

| Layer | Metrics |
|-------|---------|
| **KEM** | keygen / encaps / decaps wall-clock (median, MAD, IQR, min, max, mean, stddev, ops/sec) · a keygen+encaps+decaps total · pk/sk/ct sizes · heap high-water |
| **Signature** | keygen / sign / verify wall-clock (same stats) · a keygen+sign+verify total · pk/sig sizes |
| **TLS 1.3** | full-handshake latency · handshakes/sec · bytes-on-wire · ClientHello size (+ fragmentation flag) · a per-cell primitive-operation sum (below) — as a matrix of (KEM group × signature) |

The **classical baseline** (X25519 / Ed25519 / X25519+Ed25519) is always
included as the reference point — measured as a real primitive via OpenSSL, not
hand-waved.

### Migration phases (TLS)

Every TLS matrix cell carries a `phase` field from our migration framework:

- **`baseline`** — classical KEM group + classical signature
  (X25519 + Ed25519): what Logos runs today.
- **`phase0`** — PQ or hybrid KEM group + **classical** signature
  (e.g. X25519MLKEM768 + Ed25519): the harvest-now-decrypt-later protection
  actually deployed on today's internet.
- **`phase2`** — PQ signature (e.g. X25519MLKEM768 + ML-DSA-65): full PQ
  authentication.

### Per-operation values vs totals

Per-operation medians (±MAD) remain the primary data. In addition, every
KEM/sig row carries a `total.sum_of_medians_ns` aggregate, and every enabled
TLS cell carries a `handshake_primitive_sum` block: the sum of the primitive
operations that one handshake actually performs (hybrid groups include **both**
components — e.g. X25519MLKEM768 = 2× X25519 keygen + 2× derive + ML-KEM-768
keygen/encaps/decaps — plus the signature sign + verifies), with the exact
component list, counts and medians spelled out in the JSON so the number is
auditable. These are **sums of medians** — derived figures, labelled as such,
not measured latencies; the gap between `handshake_primitive_sum` and the
measured handshake latency is the protocol overhead.

---

## Project layout

```
pqc-bench/
  setup/         build + pin liboqs, OpenSSL 3.5+, oqs-provider (versions.env / versions.lock)
  bench/kem_sig/ bench_pq.c     primitive KEM/sig harness (liboqs + OpenSSL EVP baselines)
  bench/tls/     bench_tls.c    in-process TLS 1.3 handshake harness (OpenSSL API;
                                openssl-native + oqs-provider matrices)
                 run_tls.sh      PKI generation + three-stack phase-matrix driver
  bench/rust/    pqb-rust       pure-Rust (RustCrypto) primitive harness + dalek anchors
  bench/rust-tls/ pqb-rust-tls  rustls + aws-lc-rs TLS harness + aws-lc-rs pricing rows
  bench/lib/     assemble.py / merge helpers / miniyaml.py (zero-dep YAML)
  results/       results/<host>-<timestamp>.json  (one per run, full metadata)
  analyze/       merge.py (combine machines) + plot.py (matplotlib PNGs, optional venv)
  dashboard/     static HTML/JS (Chart.js) — no backend, GitHub-Pages deployable
  run.sh         governor + taskset + thermal wrapper + orchestrator
  config.yaml    candidate lists (extend here)
  Dockerfile     reproducible Debian-aarch64 build
```

---

## Quick start

### Prerequisites (all platforms — read this first)

- **OpenSSL ≥ 3.5 with its DEVELOPMENT files** (the project pins the 3.5.x
  LTS line): the `openssl` binary alone is **not** enough — liboqs and
  oqs-provider compile and link against libcrypto, so you need the headers
  too (`libssl-dev` on Debian, **`openssl-devel` on Fedora/RHEL**, keg-only
  Homebrew `openssl@3.5` on macOS). `make check` verifies this with a real
  compile-and-link probe against the exact OpenSSL the build will use and
  prints the right package name for your platform. Systems older than 3.5
  trigger an automatic source build (+15–30 min).
- **Rust toolchain (rustup)** — required for **two of the four measurement
  groups** (RustCrypto primitives and the rustls TLS matrix). Install stable
  via [rustup.rs](https://rustup.rs); if cargo is absent the run completes but
  those groups are skipped (with recorded reasons). The rustls harness
  compiles the AWS-LC C library on first build — several minutes, once.
- **cmake** (liboqs and the AWS-LC build), a C compiler, **git**, **python3**
  (stdlib only). `make deps` installs these on Debian-family (apt),
  Fedora/RHEL-family (dnf) and macOS (brew); other distros get the package
  list printed.
- **liboqs must be the vendored, pinned build — never a system copy.** The
  harness refuses to link a distro `liboqs-devel`: an unpinned liboqs would
  silently change what is measured (and the pinned oqs-provider expects
  exactly the pinned liboqs' headers). `make build` produces the vendored
  build; `make test` verifies the built binaries actually link it.
- Any Linux or macOS box works: non-Pi hosts run fine and are stamped
  `is_baseline_grade=false` with reasons — only a Raspberry Pi 5 under the
  controlled conditions below produces reference-grade rows.

### The make targets (all platforms — executable documentation)

The setup and run steps live in the **Makefile**, so they can't drift from
reality the way prose does; `make help` lists everything. The flow:

```bash
git clone <this repo> && cd pqc-bench
make check     # read-only: verifies the environment — including that the
               # OpenSSL the build will use has its DEVELOPMENT files
               # (compile-and-link probe) — and prints per-platform install
               # commands for anything missing (installs nothing)
make deps      # OPT-IN installer for what check reported: apt / dnf / brew
               # per platform (add RUST=1 for rustup)
make build     # C toolchain + bench binaries + both Rust harnesses (as your
               # user — it refuses to run cargo as root, and refuses to link
               # a system liboqs)
make test      # ~1-2 min verification gate (21 checks): harness correctness
               # gates, LINK-TARGET verification (vendored liboqs + pinned
               # OpenSSL, via otool/ldd), the three TLS stacks incl. the
               # native no-OQS-provider assertion, cross-implementation size
               # agreement, schema round-trip; repo-hygiene checks warn
               # without blocking
make smoke     # all-four-groups pipeline check (1 rep, 50 handshakes/cell)
make test-fedora # check+build+test in a Fedora container (podman/docker;
               # SMOKE=1 adds a smoke run) — covers the Red Hat platform
               # differences Mac+Pi testing structurally cannot catch (dnf
               # package split, lib64 defaults, x86 /proc/cpuinfo shape);
               # exercises degradation paths, produces no measurement data
make run       # the full benchmark (~30 min Pi 5 / ~36 min M3)
make merge     # rebuild dashboard/data/merged.json from the published manifest
make dashboard # serve the dashboard over HTTP (view only; never mutates data)
```

`make run`/`make smoke` handle privilege correctly per platform. The run needs
root for exactly one step — writing `performance` into the sysfs CPU-governor
files — so on Linux they cache sudo credentials once up front (`sudo -v`) and
only that step escalates (`sudo -n`); the measurement itself, including the
cargo builds and all result files, runs as your user. (The old whole-run sudo
design left root-owned `results/.work-*` and `target/` artifacts behind and
needed a fragile `sudo env RUSTUP_HOME=…` workaround for cargo — all gone.)
On macOS no escalation of any kind is used. `NOSUDO=1 make run` skips the
sudo attempt and honestly records the governor demerit. `build`'s skip logic uses live checks (artifacts + `openssl version`
against the lock), never stamp files — upgrading OpenSSL triggers a rebuild
instead of being silently masked.

### On a Raspberry Pi 5 (the real measurement target)

Follow **[RUNNING-ON-YOUR-RPI5.md](RUNNING-ON-YOUR-RPI5.md)** for the
Pi-specific context (cooling, PSU, governor, baseline-grade); the commands are
the same targets: `make check && make build && make test && make run`.

**On `sudo`:** it is **optional, not a prerequisite.** The only thing it does is
set the CPU governor to `performance` — none of the crypto needs root. `./run.sh`
runs fine without it: it warns, skips the governor step, completes the run, and
the results JSON is automatically stamped `is_baseline_grade=false` (governor
demerit). So use `sudo` when you want a baseline-grade reference run; drop it for
a quick local run you don't intend to submit.

`./run.sh --smoke` runs tiny iteration counts as a fast pipeline check.
`./run.sh --kemsig-only` / `--tls-only` scope the run. `--iters/--warmup/--reps`
override the `config.yaml` knobs.

### On macOS (cross-platform reference / smoke testing)

Same targets: `make check` tells you what to `brew install` (or `make deps`
does it for you), then `make build && make test && make smoke`. Runs are
stamped `is_baseline_grade=false` with reasons, by design:

> **macOS runs are cross-platform / smoke data, never baseline-grade — by
> design, for three concrete reasons:**
> 1. **Not a Raspberry Pi**, so it fails the gate's first condition outright.
> 2. **No userspace cycle counter, and ~1 µs timer granularity.** macOS exposes
>    no readable PMU cycle counter and its wall-clock quantizes to ~1 µs steps —
>    a ~10% floor on the fastest ops (ML-KEM ~10 µs), negligible for anything
>    ≥100 µs (McEliece, FrodoKEM). (See "Timing source" under Measurement
>    methodology below.)
> 3. **No Linux cpufreq governor, and core-pinning isn't guaranteed.** Two of the
>    noise-control knobs the gate relies on — `performance` governor and a pinned
>    core — aren't available, and the build flags aren't `cortex-a76` either.
>
> Every macOS results file records `is_baseline_grade=false` with the exact
> reasons, and the dashboard shows such runs labelled **"cross-platform
> reference — not baseline-grade"** (shown and labelled, never mixed with or
> mistaken for the Pi reference). They still produce
> **useful cross-platform numbers** (the heavier McEliece/FrodoKEM ops are barely
> affected by the timer floor) — they just can't meet the controlled reference
> bar, hence smoke-only.

### Docker (reproducible build — build only, never run)

Docker is for reproducibly **building** the pinned C toolchain (liboqs /
OpenSSL / oqs-provider), not for running the benchmark:

```bash
docker build -t pqc-bench .   # builds + pins the C toolchain inside the image
```

> **Coverage note:** the image covers the **C toolchain only** — it installs no
> Rust, so the RustCrypto and rustls harnesses are not built in it, and it has
> not been re-verified since those measurement groups were added. Its Debian 12
> base also predates the system-OpenSSL-3.5 path, so `setup.sh` source-builds
> OpenSSL inside the image. Treat it as a legacy convenience for the C
> toolchain; the verified paths are the bare-metal ones above.

**Run the measurement bare-metal on the host.** A container can't reliably set
the CPU governor, pin to an isolated core, or read the Pi's thermal/throttle
sensors — the noise-control knobs the reference-grade gate relies on — so an
in-container run could never be baseline-grade and would only add jitter. Build
in Docker if you like; then run `./run.sh` on the host.

---

## Measurement methodology (why the numbers are credible)

`run.sh` is the wrapper that makes a number defensible:

- **CPU governor → `performance`** (Linux; needs `sudo`). Recorded before/after.
  If it can't be set (e.g. not root) the run **continues anyway**: it warns,
  proceeds, and the missing governor becomes an `is_baseline_grade=false`
  demerit. `sudo` is only ever for this step — never for the crypto.
- **Core pinning via `taskset -c 3`.** This is a **single-operation latency**
  benchmark (one keygen, one encaps, one sign — timed in isolation), not a
  parallel-throughput one, so pinning the whole sweep to one core keeps that
  core's cache warm and removes cross-core migration scheduling noise, which
  tightens the median and MAD. The Pi 5 has 4 cores (0–3); core **3** is chosen
  because core 0 typically absorbs the most OS/IRQ/RPS work. The pinned core and
  exact `taskset` command are recorded.
  - *Planned (separate axis):* a multi-core **throughput/scaling** mode — run an
    op across 1..N cores and report ops/sec plus scaling efficiency per
    algorithm. Some schemes (SLH-DSA, and later STARK proving) parallelize far
    better than others, so it's a worthwhile dimension — but kept **separate**
    from these per-op latency numbers, not mixed into them.
- **Thermal/clock trace.** A background sampler logs ARM clock
  (`vcgencmd measure_clock arm`) and SoC temperature (`vcgencmd measure_temp`)
  ~once a second for the whole run. The full trace is embedded in the results
  JSON, and **thermal throttling** (`vcgencmd get_throttled`, plus a clock-droop
  heuristic) is detected and flagged — a throttled run is not baseline-grade.
- **Warmup + N timed iterations, multiple repetitions.** Primary metric is
  wall-clock nanoseconds via `clock_gettime(CLOCK_MONOTONIC)`. We report
  **median, MAD, IQR, min, max, mean, stddev, ops/sec**, plus per-repetition
  medians — not just a mean.
- **Timing source — two clocks, honestly recorded.** There are two ways to time
  an op:
  1. **Cycle-based** via the ARM hardware cycle counter (`PMCCNTR_EL0`) — the
     most precise, but on Linux **userspace can't read it by default**: the
     register traps unless a kernel module enables the userspace PMU (e.g.
     `enable_arm_pmu`).
  2. **Time-based** wall-clock via `clock_gettime(CLOCK_MONOTONIC)` — always
     available, and accurate enough for the millisecond/microsecond ranges here.

  The harness probes the cycle counter and, when it isn't available, **falls
  back to wall-clock and records exactly that** in the JSON
  (`run.cycles_available=false` + the reason). **On a stock machine the cycle
  counter is not available, so runs use the wall-clock timer by default** — and
  both published runs reflect this: the RPi5 baseline and the macOS run *both*
  have `cycles_available=false` (both wall-clock). The remaining difference
  between them is wall-clock **granularity**, not clock *type*: the Pi's
  wall-clock lands on fractional microseconds, while macOS quantizes to ~1 µs
  steps — a ~10% resolution floor on the fastest ops (ML-KEM keygen ~10 µs),
  negligible for anything ≥100 µs (McEliece, FrodoKEM).
- **CPU features / Keccak acceleration.** NEON, SHA2, SHA3, SHA512, AES, PMULL
  are detected (`/proc/cpuinfo` on Linux, `sysctl` on macOS). **Note:** the
  Cortex-A76 has the SHA2/AES extensions but **not** the ARMv8.2 SHA3
  extension, so on the Pi 5 Keccak runs on NEON/scalar code — the results record
  both the hardware capability and whether liboqs was compiled with SHA3
  instructions, so this is explicit rather than assumed.

### The AArch64-optimized backend

liboqs is built with `OQS_DIST_BUILD=OFF` and the pinned flags so the optimized
aarch64 ML-KEM backend (`mlkem-native`) and Falcon/Keccak asm are compiled in.
`setup/setup.sh` extracts the proof from the generated `oqsconfig.h` (e.g.
`OQS_ENABLE_KEM_ml_kem_768_aarch64 1`) into `versions.lock`, which is stamped
into every results file under `toolchain.liboqs_opt_defines`.

---

## Methodology & trustworthiness (verify it yourself)

Every claim below points at the exact code so you can read it, not take our word.
All `bench_pq.c` references are `bench/kem_sig/bench_pq.c`.

1. **Correctness gate — broken crypto emits *zero* numbers.** Before any timing,
   each algorithm runs a full round-trip and asserts it: for KEM,
   keygen→encaps→decaps then `memcmp(ss_encaps, ss_decaps)`
   (`bench_pq.c:357-363`); for signatures, keygen→sign→`verify` must succeed
   (`bench_pq.c:428-434`). On any failure, `die()` prints to **stderr** and
   `exit(3)` (`bench_pq.c:303-307`) — and the JSON is only printed *after* all
   measurement (`bench_pq.c:372-381`), so a failed gate yields **no stdout at
   all**. The gate runs once, *outside* the timed loop. A runtime guard
   (`must_measure`, `bench_pq.c:311-315`) also aborts if a timed op ever fails
   mid-run. *Verify it:* flip one byte of the decaps shared secret right before
   `bench_pq.c:362`, rebuild, run — the process exits `3` with empty stdout.

2. **No dead-code elimination — the `volatile` sink.** At `-O3` the compiler may
   delete work whose result is never observed. Each timed op folds an output
   byte into a file-scope `volatile uint64_t g_sink` (`bench_pq.c:300`; uses at
   `:333,:336,:339,:407,:410,:486`), forcing the store to be materialized so the
   crypto call **cannot** be optimized away. Without it the loop could time
   nothing and report meaningless near-zero numbers.

3. **What is timed — only the op, never setup.** The timed region brackets a
   single `fn(ctx)` call between two `now_ns()` reads (`bench_pq.c:274-281`);
   per-rep warmup runs *outside* it (`bench_pq.c:272-273`). Inputs are canonical
   and pre-validated, so e.g. KEM decaps (`bench_pq.c:337-339`) times one
   `OQS_KEM_decaps` and nothing else. For the X25519 baseline, keygen is timed
   separately (`bench_pq.c:507`), a stable key is re-primed *outside* timing
   (`bench_pq.c:509`), then derive is timed alone (`bench_pq.c:510`) — setup is
   never folded into a measured number.

4. **Per-op auto-calibration with clamps.** `calibrate_op` (`bench_pq.c:209-250`)
   runs a doubling probe (`:223-230`, also cache warmup) to estimate per-op cost
   `est_ns` (`:231`), then picks iterations to hit `target_time_ms` of real work
   (`:234-235`), clamped to `[min_samples, max_iters]` (`:236-237`). So a fast
   18 µs keygen and a 0.74 s SLH-DSA sign each get the iteration count *they*
   need: slow ops floor at `min_samples` (30), fast ops ceil at `max_iters`
   (20000). The chosen `timed_iters` and `calib_est_ns` are recorded per op.

5. **Robust statistics — median + MAD.** `compute_stats` (`bench_pq.c:111-146`)
   reports median, MAD, IQR, q1/q3, min, max, mean, stddev, ops/sec, plus
   per-repetition medians (`print_stats_json`, `bench_pq.c:184-203`). The
   headline metric is the **median**, with **MAD** as spread: timing
   distributions are right-skewed with a hard floor (true cost) and a long tail
   of OS-scheduling/interrupt contamination that drags mean/stddev but not
   median/MAD. Mean and stddev are kept in the JSON so the skew is visible. The
   clock is `clock_gettime(CLOCK_MONOTONIC)` (`bench_pq.c:44-48`); userspace PMU
   cycles are probed and honestly reported absent when they trap
   (`probe_pmu`, `bench_pq.c:66-86`).

6. **`is_baseline_grade` demerit gate.** Computed in
   `bench/lib/assemble.py:155-168` as a demerit accumulator — the flag is `true`
   only if *every* condition holds: real Pi (`:157`), `performance` governor
   (`:160`), core-pinned (`:162`), `cortex-a76` build flags (`:164`), and no
   thermal throttling (`:166`). Throttling is read from `vcgencmd get_throttled`
   bits 2/18 plus a clock-droop heuristic (`assemble.py:91-98,:110-113`). Any
   failure appends a human-readable reason and flips the flag to `false`; the
   dashboard and `plot.py` default to baseline-grade runs only.

---

## Reproducibility & provenance

- **Pinned versions** live in `setup/versions.env` (liboqs `0.15.0`, OpenSSL
  pinned to the **3.5.x LTS line** on every platform — keg-only Homebrew
  `openssl@3.5` on macOS, Debian 13's system 3.5.x on the Pi — so cross-machine
  TLS numbers never compare different OpenSSL minor lines; oqs-provider
  `0.9.0`). After cloning, `setup.sh` records the **actually resolved git
  commits** and the **exact build flags + compiler version** into
  `setup/versions.lock`.
- **Acceleration provenance, empirically determined.** Every KEM/sig row
  carries an `acceleration` field with two independent axes: the *arithmetic
  path* (hand-written asm vs portable code, derived from the recorded build
  defines / Rust provenance) and the *symmetric path* (which primitive the hot
  loop uses — AES / SHA-2 / SHA-3-SHAKE / none — where that implementation
  comes from, and whether it reaches hardware instructions on this CPU). The
  per-algorithm routing was established by **differential builds** (toggling
  `OQS_USE_{SHA2,AES,SHA3}_OPENSSL` and measuring which rows move), not by
  reading configuration — necessary because e.g. liboqs 0.15's SLH-DSA bundles
  its own portable SHA-2 and ignores the OQS symmetric layer entirely, while
  its sibling SPHINCS+ routes through it.
- **Results schema `2.0.0`.** Every KEM/sig row carries `implementation`
  (which library produced the measurement: `liboqs`, `openssl`, `rustcrypto`,
  `oqs-provider`, `openssl-native`, `rustls-awslc`; formerly named `backend`),
  and every TLS cell carries `implementation` + `phase` + `sig_alg` and the
  `handshake_primitive_sum` block. Older (schema `1.0.0`) result files are
  **never rewritten** — `analyze/merge.py` injects the equivalent values at
  merge time (`backend`→`implementation`, phase inference, derived totals).
- **Every results JSON carries full environment metadata**: RPi model, RAM,
  kernel, OS, governor, the clock/temp trace during the run, compiler version,
  liboqs/oqs-provider/OpenSSL versions+commits, build flags, and the candidate
  list. A macOS smoke file and an RPi5 baseline file can never be confused.
- **Identical flags for every candidate:** `-O3 -mcpu=cortex-a76` on the Pi.
  Document your `gcc`/`clang` version — it is auto-captured in `versions.lock`
  (`CC_VERSION`).

### `is_baseline_grade`

A **reference-measurement quality gate**, not a deployment requirement. It marks
whether a run was produced under controlled, reproducible *reference* conditions,
so the numbers are comparable across algorithms and across machines. It is `true`
**only** when all hold: real Raspberry Pi · `performance` governor · core-pinned ·
`cortex-a76` build flags · no thermal throttling. Otherwise it is `false` with a
list of reasons.

- **What it is:** a label that says "this run is clean enough to sit in the
  cross-algorithm / cross-machine reference comparison." The dashboard and
  `plot.py` default to baseline-grade runs only, so noisy runs don't distort the
  picture.
- **What it is *not*:** a claim about how nodes must be configured in production.
  Real deployments are heterogeneous (different SoCs, governors, thermals) —
  that's a separate question this flag does not speak to.
- A run that doesn't meet the gate **isn't wrong** — it's just flagged
  `is_baseline_grade=false` with the reasons and kept out of the reference set.
  The macOS cross-platform runs are exactly this: useful, honest numbers that
  simply aren't reference-grade.

---

## Candidates (edit `config.yaml`)

- **KEM:** ML-KEM-512/768/1024; hybrids X25519MLKEM768, SecP256r1MLKEM768
  (hybrids are benchmarked in the TLS layer; at the primitive layer liboqs
  exposes them only as TLS groups, so they show as `enabled:false` there).
  Code-based + conservative-LWE backups: Classic McEliece
  348864/460896/460896f/6688128/6960119/8192128 (tiny ciphertext, slow keygen)
  and FrodoKEM 640/976/1344 in **both AES and SHAKE variants** — same
  algorithm and arithmetic, different symmetric primitive, added as the
  controlled test of the hardware-AES attribution for FrodoKEM's
  cross-platform behaviour (on the M3 the SHAKE variants measure ~5–6.6×
  slower than AES). Baseline: **X25519**.
- **Signatures:** ML-DSA-44/65/87; hash-based **both** SLH-DSA (FIPS 205 final,
  `SLH_DSA_PURE_SHA2_{128s,128f,192f,256f}`) **and** the round-3
  `SPHINCS+-SHA2-*-simple` sets; Falcon/FN-DSA-512/1024. Baseline: **Ed25519**.

  > **Comparability note (SPHINCS+ vs SLH-DSA).** Round-3 SPHINCS+ and FIPS 205
  > SLH-DSA are **different algorithms**, not a relabelling. The earlier
  > (now-retired generation) RPi5 baselines measured only the SPHINCS+ sets;
  > the config measures both generations side by side, so runs (a) stay
  > directly comparable to that history via the SPHINCS+ rows and (b) carry
  > the standardised SLH-DSA numbers. Don't compare an SLH-DSA row against an old SPHINCS+ row as if
  > they were the same scheme. The SLH-DSA identifiers exist in our pinned
  > liboqs 0.15.0 build, so this needs no library upgrade; liboqs 0.16.0
  > removes SPHINCS+ entirely, at which point the SPHINCS+ rows retire.
- **RustCrypto second source:** the same ML-KEM / ML-DSA / SLH-DSA parameter
  sets (and X25519/Ed25519 anchors) measured again from pure-Rust
  implementations — rows join by `(kind, alg)` across `implementation`, and
  `assemble.py` cross-checks that both implementations report identical
  encoded sizes (a mismatch is reported loudly as a bug/spec disagreement,
  never as a benchmark result).
- **TLS:** two matrices (see "What gets measured"): the `openssl-native` phase
  matrix (baseline / phase0 / phase2, Ed25519 and ML-DSA certificates) and the
  full `oqs-provider` matrix — always including the classical
  **X25519 + Ed25519** pair, measured natively.

Classic McEliece and FrodoKEM are now measured (above). **HQC** is not — it is
not enabled in the linked liboqs 0.15.0 build (disabled upstream after the
IND-CCA2 implementation issue), so it is intentionally omitted rather than
listed-and-disabled; re-add it once linked against a liboqs that re-enables it.
Add further algorithms by uncommenting/adding entries — the harness skips
anything your liboqs build doesn't enable (and says so).

---

## Output & analysis

- `results/<hostname>-<timestamp>.json` — one self-describing file per run.
- `analyze/merge.py` — with **no arguments**, merges the **published set**
  pinned in `analyze/published_runs.txt` into `dashboard/data/merged.json`
  (explicit manifest, so ad-hoc dev runs in `results/` never leak into the
  published dataset); pass explicit files/globs for an ad-hoc merge. Keeps
  each run distinct; never mixes baseline with smoke.
- `analyze/plot.py` — matplotlib PNGs for papers (optional; install into
  `analyze/.venv` via `analyze/requirements.txt` to keep system python clean —
  it gracefully skips if matplotlib is absent).
- `dashboard/` — static, no-backend dashboard (see `dashboard/README.md`):
  the TLS migration-phase view (Pi and Mac side by side, latency + bytes with
  ×multipliers), the full three-stack handshake matrix, cross-implementation
  primitive comparison with an always-visible acceleration table, the original
  security-level charts (log axes, classical reference lines), and a
  deliberate-absences panel. Serve over HTTP (`python3 -m http.server`) or
  deploy the folder to GitHub Pages.

---

## Contributing your RPi5 results

The whole point is a **shared, aggregated baseline**: the more Raspberry Pi 5
results we collect under identical conditions, the more confident the migration-
cost picture. If you have a Pi 5, please contribute a run — it takes one command
and a pull request.

### 1. Run under baseline conditions

For your numbers to count as baseline-grade, the run must satisfy the
`is_baseline_grade` gate (real Pi 5 · `performance` governor · core-pinned ·
`cortex-a76` flags · no thermal throttling). To give it the best shot:

- **Use a Raspberry Pi 5** with active cooling (the official Active Cooler or a
  fan). PQ signing (esp. SLH-DSA) runs the core hot for a while; without cooling
  you *will* throttle and the run is flagged non-baseline.
- **Use the official 27 W USB-C PSU.** Under-voltage also trips the throttle flag.
- **Run on a quiet machine** (close other workloads) so core 3 stays clean.
- **Don't edit `config.yaml`'s candidate list** if you want your run to be
  directly comparable to others. (Extending it is fine — just say so in your PR;
  extra algorithms simply add columns.)

```bash
git clone <this repo> && cd pqc-bench
make check && make build && make test
make run     # sudo (with the required rustup env) is handled for you
```

A full run takes ~30 min on a Pi 5 (hash-based signing dominates). To check the
pipeline first without committing to the full run, `make smoke` — but only a
**full** run (not smoke) counts as a submission.

### 2. Confirm it's baseline-grade

When the run finishes, the summary prints `baseline-grade (RPi5): True`. Verify
in the JSON too:

```bash
f=$(ls -t results/*.json | head -1)
python3 -c "import json;d=json.load(open('$f'));print('baseline_grade:',d['is_baseline_grade']);\
print('reasons:',d['baseline_grade_reasons']);\
print('throttled:',d['thermal_trace']['throttling_detected']);\
print('aarch64 ML-KEM backend:', 'ml_kem_768_aarch64 1' in d['toolchain']['liboqs_opt_defines'])"
```

You want `baseline_grade: True`, `reasons: []`, `throttled: False`, and the
backend line `True`. If `is_baseline_grade` is false, the printed reasons tell
you what to fix (usually cooling/PSU/governor) — fix and re-run.

### 3. Submit it

Your `results/<hostname>-<timestamp>.json` is fully self-describing (host model,
kernel, OS, governor, clock/temp trace, compiler + liboqs/oqs-provider/OpenSSL
commits, build flags). It contains your **hostname** and Pi model and nothing
else identifying — if you'd rather not share the hostname, prepend
`HOSTNAME=mypi5` to the sudo run line, or just rename the file before
submitting.

`results/*.json` is git-ignored by default (so you never accidentally commit
local experiments), so add yours explicitly:

```bash
git checkout -b results/<your-handle>-pi5
git add -f results/<hostname>-<timestamp>.json
git commit -m "results: RPi5 baseline from <your-handle>"
# push to your fork and open a PR
```

**PR checklist** (maintainers will look for these):

- [ ] `is_baseline_grade: true` with empty `baseline_grade_reasons`
- [ ] `thermal_trace.throttling_detected: false`
- [ ] `host.is_rpi: true` and `host.rpi_model` mentions "Raspberry Pi 5"
- [ ] `run.governor_after: performance` and `run.pinned: true`
- [ ] `toolchain.cflags_target: cortex-a76`
- [ ] full run (not `--smoke`): `run.repetitions` is the `config.yaml` value
      (5), not 1 — smoke runs record `repetitions: 1`
- [ ] all four measurement groups present (`toolchain.rust.available: true`;
      rustcrypto / aws-lc-rs / rustls-awslc rows in the JSON) — if the Rust
      groups are missing, revisit the sudo env line above
- [ ] unmodified candidate list (or extensions noted in the PR description)

Once merged, your file joins `results/` and gets a line in
`analyze/published_runs.txt` (the explicit manifest of published runs); anyone
can then regenerate the aggregated dataset and dashboard with
`python3 analyze/merge.py`. The dashboard's run selector will then include
your Pi alongside everyone else's.

> Prefer not to use GitHub? Open an issue and attach the JSON file instead — a
> maintainer will add it.

---

## Limitations

- **macOS is smoke-only** (see above): coarse timer, no governor/pinning,
  fallback flags.
- **Userspace cycle counts** require a kernel PMU module; default is time-based.
- **Heap/stack memory** is best-effort (`mallinfo2` on glibc; reported
  unavailable elsewhere); pk/sk/ct/sig **sizes** are authoritative.
- **TLS handshakes are in-process over memory BIOs** — this isolates crypto
  cost cleanly (no socket/scheduler noise) but is not a network RTT model;
  ClientHello fragmentation is flagged against a typical 1400-byte MSS.
- **Docker is build-only.** The benchmark is not run in a container — a
  container can't reliably control the governor, core pinning, or throttle
  detection, so measurement runs bare-metal on the host (see the Docker section).

## Future phase (not implemented)

`config.yaml` reserves a `zk:` section for SNARK/STARK proving/verification
benchmarks; the results schema and dashboard are structured to absorb it later.
