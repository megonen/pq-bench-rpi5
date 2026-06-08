# pq-bench-rpi5

A reproducible, general-purpose **post-quantum cryptography benchmark** whose
baseline target is the **Raspberry Pi 5** (Broadcom BCM2712, Cortex-A76,
aarch64). Anyone can run it on their own Pi 5 and the results aggregate and
compare apples-to-apples.

**Framing — migration cost.** How much does moving from the cryptography Logos
uses *today* (X25519 key exchange + Ed25519 signatures) to PQ candidates cost on
validator-grade hardware? Every chart draws that classical baseline as the
reference line, so the PQ "tax" is always visible.

Phase 1 covers **PQ KEMs**, **PQ signatures**, and **PQ TLS 1.3 handshakes**.
Hooks are left for a later SNARK/STARK phase (see `config.yaml`); it is not
implemented yet.

---

## What gets measured

| Layer | Metrics |
|-------|---------|
| **KEM** | keygen / encaps / decaps wall-clock (median, MAD, IQR, min, max, mean, stddev, ops/sec) · pk/sk/ct sizes · heap high-water |
| **Signature** | keygen / sign / verify wall-clock (same stats) · pk/sig sizes |
| **TLS 1.3** | full-handshake latency · handshakes/sec · bytes-on-wire · ClientHello size (+ fragmentation flag) — as a matrix of (KEM group × signature) |

The **classical baseline** (X25519 / Ed25519 / X25519+Ed25519) is always
included as the reference point — measured as a real primitive via OpenSSL, not
hand-waved.

---

## Project layout

```
pq-bench-rpi5/
  setup/         build + pin liboqs, OpenSSL 3.5+, oqs-provider (versions.env / versions.lock)
  bench/kem_sig/ bench_pq.c     primitive KEM/sig harness (liboqs + OpenSSL EVP baselines)
  bench/tls/     bench_tls.c    in-process TLS 1.3 handshake harness (OpenSSL API)
                 run_tls.sh      PKI generation + (KEM × sig) matrix driver
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

### On a Raspberry Pi 5 (the real measurement target)

```bash
git clone <this repo> && cd pq-bench-rpi5
./setup/setup.sh                 # build + pin liboqs, OpenSSL 3.5+, oqs-provider
sudo ./run.sh                    # sudo needed to set the CPU governor
python3 analyze/merge.py results/*.json -o dashboard/data/merged.json
# open dashboard/index.html (or deploy dashboard/ to GitHub Pages)
```

`./run.sh --smoke` runs tiny iteration counts as a fast pipeline check.
`./run.sh --kemsig-only` / `--tls-only` scope the run. `--iters/--warmup/--reps`
override the `config.yaml` knobs.

### On macOS (development / smoke testing only)

```bash
brew install cmake openssl@3 git
./setup/setup.sh
./run.sh --smoke                 # produces valid JSON; stamped is_baseline_grade=false
```

> **macOS runs are never baseline data.** No `performance` governor, no
> `taskset` core pinning, and the build falls back to `-O3` (not
> `-mcpu=cortex-a76`). Every results file records `is_baseline_grade=false`
> with the exact reasons, and the dashboard hides such runs by default. macOS
> `clock_gettime` is also only microsecond-resolution; the Pi's is nanosecond.

### Docker (reproducible build)

```bash
docker build -t pq-bench-rpi5 .
docker run --rm -v "$PWD/results:/app/results" pq-bench-rpi5 ./run.sh --smoke
```
See the `Dockerfile` header for granting governor/sensor access for real runs.

---

## Measurement methodology (why the numbers are credible)

`run.sh` is the wrapper that makes a number defensible:

- **CPU governor → `performance`** (Linux). Recorded before/after; warns if it
  couldn't be set (e.g. not root).
- **Core pinning via `taskset -c 3`.** The Pi 5 has 4 cores (0–3); core 3 is
  chosen to stay clear of CPU0, where the kernel tends to steer IRQs/RPS. The
  pinned core and exact `taskset` command are recorded.
- **Thermal/clock trace.** A background sampler logs ARM clock
  (`vcgencmd measure_clock arm`) and SoC temperature (`vcgencmd measure_temp`)
  ~once a second for the whole run. The full trace is embedded in the results
  JSON, and **thermal throttling** (`vcgencmd get_throttled`, plus a clock-droop
  heuristic) is detected and flagged — a throttled run is not baseline-grade.
- **Warmup + N timed iterations, multiple repetitions.** Primary metric is
  wall-clock nanoseconds via `clock_gettime(CLOCK_MONOTONIC)`. We report
  **median, MAD, IQR, min, max, mean, stddev, ops/sec**, plus per-repetition
  medians — not just a mean.
- **Cycles mode (optional).** The harness probes whether the userspace ARM PMU
  cycle counter (`PMCCNTR_EL0`) is readable. By default on Linux it traps
  (needs a kernel module like `enable_arm_pmu`); we then **fall back to
  time-based and say so** in the JSON (`run.cycles_available=false` + reason).
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

## Reproducibility & provenance

- **Pinned versions** live in `setup/versions.env` (liboqs `0.15.0`, OpenSSL
  `3.5.0`/`≥3.5`, oqs-provider `0.9.0`). After cloning, `setup.sh` records the
  **actually resolved git commits** and the **exact build flags + compiler
  version** into `setup/versions.lock`.
- **Every results JSON carries full environment metadata**: RPi model, RAM,
  kernel, OS, governor, the clock/temp trace during the run, compiler version,
  liboqs/oqs-provider/OpenSSL versions+commits, build flags, and the candidate
  list. A macOS smoke file and an RPi5 baseline file can never be confused.
- **Identical flags for every candidate:** `-O3 -mcpu=cortex-a76` on the Pi.
  Document your `gcc`/`clang` version — it is auto-captured in `versions.lock`
  (`CC_VERSION`).

### `is_baseline_grade`

The single gate that protects the dataset. It is `true` **only** when all hold:
real Raspberry Pi · `performance` governor · core-pinned · `cortex-a76` build
flags · no thermal throttling. Otherwise it is `false` with a list of reasons.
The dashboard and `plot.py` default to baseline-grade runs only.

---

## Candidates (edit `config.yaml`)

- **KEM:** ML-KEM-512/768/1024; hybrids X25519MLKEM768, SecP256r1MLKEM768
  (hybrids are benchmarked in the TLS layer; at the primitive layer liboqs
  exposes them only as TLS groups, so they show as `enabled:false` there).
  Baseline: **X25519**.
- **Signatures:** ML-DSA-44/65/87; SLH-DSA (SPHINCS+) variants;
  Falcon/FN-DSA-512/1024. Baseline: **Ed25519**.
- **TLS:** matrix of configured KEM groups × signature algorithms, always
  including the classical **X25519 + Ed25519** pair.

Add FrodoKEM / HQC / Classic McEliece etc. by uncommenting/adding entries — the
harness skips anything your liboqs build doesn't enable (and says so).

---

## Output & analysis

- `results/<hostname>-<timestamp>.json` — one self-describing file per run.
- `analyze/merge.py results/*.json -o dashboard/data/merged.json` — merge runs
  from many machines into one dataset (keeps each run distinct; never mixes
  baseline with smoke).
- `analyze/plot.py` — matplotlib PNGs for papers (optional; install into
  `analyze/.venv` via `analyze/requirements.txt` to keep system python clean —
  it gracefully skips if matplotlib is absent).
- `dashboard/` — static, no-backend dashboard: grouped bars by security level,
  size-vs-speed scatter, TLS handshakes/sec, and ClientHello size — each with
  the classical baseline drawn as a reference line. Deploy the folder to GitHub
  Pages, or open `index.html` via any static server.

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
git clone <this repo> && cd pq-bench-rpi5
./setup/setup.sh                 # build + pin liboqs / OpenSSL 3.5+ / oqs-provider
sudo ./run.sh                    # sudo lets it set the performance governor
```

A full run takes a while (SLH-DSA signing dominates). To check the pipeline
first without committing to the full run, use `sudo ./run.sh --smoke` — but only
a **full** run (not `--smoke`) counts as a submission.

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
else identifying — if you'd rather not share the hostname, set a name first with
`HOSTNAME=mypi5 sudo ./run.sh`, or just rename the file before submitting.

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
- [ ] full run (not `--smoke`): `run.timed_iters` is the `config.yaml` value, not 25
- [ ] unmodified candidate list (or extensions noted in the PR description)

Once merged, your file joins `results/`; anyone can regenerate the aggregated
dataset and dashboard with
`python3 analyze/merge.py results/*.json -o dashboard/data/merged.json`. The
dashboard's run selector will then include your Pi alongside everyone else's.

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
- A run inside Docker is not baseline-grade unless you grant it governor + Pi
  sensors (see `Dockerfile`).

## Future phase (not implemented)

`config.yaml` reserves a `zk:` section for SNARK/STARK proving/verification
benchmarks; the results schema and dashboard are structured to absorb it later.
