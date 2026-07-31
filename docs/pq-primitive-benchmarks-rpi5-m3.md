# Post-Quantum Primitive Benchmarks — Raspberry Pi 5 and Apple M3

This is the companion measurement note to *Post-Quantum Primitive Candidates for the Blend Protocol*. Where the candidates document defers concrete timings with the phrase that they were *measured on a Raspberry Pi 5 and a MacBook Air M3*, this note supplies those numbers: per-primitive key-encapsulation, signature, and TLS 1.3 handshake costs for the post-quantum candidates relevant to Logos Blockchain and the Bedrock stack. Every figure here is taken directly from the benchmark harness' result JSONs; none is hand-estimated.


## Scope and platforms

Two platforms were measured, and the distinction between them is load-bearing throughout this note:

- **RPi5 (cortex-a76, baseline)** — a Raspberry Pi 5 (Broadcom BCM2712, Cortex-A76, aarch64). This is the Logos validator reference baseline: the run is *baseline-grade* (`performance` governor, pinned to an isolated core, `-O3 -mcpu=cortex-a76`, no thermal throttling), so its numbers are the controlled reference.
- **Apple M3 (apple-m3, cross-ref)** — an Apple M3 (arm64-darwin), liboqs rebuilt from source with `-O3 -mcpu=native` (resolved to `apple-m3`). This run is `is_baseline_grade=false` by design (not a Pi, unpinned, no governor control on macOS). It is a full reps=5 auto-calibrated measurement, but it is a **cross-platform reference**, not a controlled validator baseline.

The measured set: ML-KEM (512/768/1024), Classic McEliece (348864 / 460896 / 460896f / 6688128 / 6960119 / 8192128), FrodoKEM (640/976/1344-AES); ML-DSA (44/65/87), Falcon (512/1024), SLH-DSA / SPHINCS+ (SHA2 128f/128s/192f/256f); and a TLS 1.3 handshake matrix of ML-KEM / hybrid key-exchange groups against PQ server-auth signatures. The classical references Logos uses today — X25519 key exchange and Ed25519 signatures — are measured alongside as the comparison line.


## Methodology

The harness is built to make each number defensible rather than merely plausible:

- **Correctness gate.** Before any timing, each algorithm runs a full round-trip and asserts it — for a KEM, `keygen → encaps → decaps` then a constant-time compare of the two shared secrets (`ss_encaps == ss_decaps`); for a signature, `keygen → sign → verify`. A failure aborts with no output, so broken crypto can never emit a timing.
- **No dead-code elimination.** Every timed operation folds an output byte into a `volatile` sink, so the compiler at `-O3` cannot optimise the crypto call away and leave the loop timing nothing.
- **Robust statistics.** The headline figure is the **median**, with **MAD** (median absolute deviation) as the spread. Timing distributions have a hard floor (true cost) and a long scheduling-noise tail that drags the mean; median and MAD resist that tail. MAD is reported here next to every median — including where it is large.
- **Per-operation auto-calibration.** Each operation is timed for ~250 ms of real work, with a floor of 30 samples and a ceiling of 20000 iterations, across 5 repetitions (fresh process each). A fast 10 µs keygen and a 0.7 s signature each get an appropriate sample count without per-algorithm hand-tuning.
- **Measurement-grade gate.** Each run records `is_baseline_grade` — true only under controlled reference conditions (real Pi, performance governor, core pinning, `cortex-a76` flags, no throttling). It gates *comparability*, not correctness; see below.


## Reading the numbers correctly

Three things must be held in mind before comparing any two figures in this note.


### Backend asymmetry — a three-way split

Not all of these algorithms are accelerated equally inside liboqs 0.15.0, and the difference is *per-scheme*, verified against each run's `toolchain.liboqs_opt_defines`. Comparing a hand-optimised assembly primitive against a portable-C one is meaningful only if the difference is flagged — so every KEM and signature row below carries one of three markers:

- **Ⓐ — asm (tuned-vs-tuned).** A dedicated aarch64 assembly backend is compiled in on **both** platforms. Applies to **ML-KEM** (mlkem-native) and **Falcon**. These are optimised-vs-optimised comparisons.
- **Ⓑ — portable-C + hardware hash.** No dedicated arithmetic asm backend; the scheme runs portable-C, but its Keccak/SHA-2 hashing uses hardware instructions. Applies to **ML-DSA** and **SLH-DSA (SPHINCS+)**. Importantly, the **M3 also has the ARMv8.2 SHA3 instruction** (`OQS_USE_ARM_SHA3_INSTRUCTIONS`), which the Cortex-A76 lacks — a genuine M3 advantage on these hash-heavy schemes.
- **Ⓒ — portable-C (portable-vs-portable).** No dedicated backend on either platform. Applies to **Classic McEliece** and **FrodoKEM**. (Frodo's *-AES* variants use the hardware AES instruction, present on both the A76 and the M3; McEliece gets no special instruction help.) These are reference-C-vs-reference-C comparisons.

So an Ⓐ ML-KEM number and a Ⓒ McEliece number are not the same kind of measurement, and the markers are there to stop them being read as if they were.


### Timing granularity

Both platforms time with a wall-clock, not a cycle counter: `cycles_available` is **false** in all four runs (the userspace ARM PMU cycle counter `PMCCNTR_EL0` traps without a kernel module, so the harness falls back to `clock_gettime` and records that it did). The relevant difference is therefore **granularity, not clock type**: the Pi's wall-clock lands on fractional microseconds (e.g. ML-KEM-512 keygen 18.315 µs), while macOS quantises to ~1 µs steps (the same op reads as a flat 10 µs). That ~1 µs floor is roughly a 10% resolution limit on the fastest operations (~10 µs ML-KEM) and is negligible for anything ≥100 µs (all of McEliece and FrodoKEM). It should be read as *macOS has coarser wall-clock granularity*, nothing more.


### Measurement grade

The Pi runs are baseline-grade; the M3 runs are `is_baseline_grade=false` by design. That flag is a reference-comparison quality gate, not a verdict on the hardware: the M3 numbers are full reps=5 auto-calibrated measurements and are perfectly usable as a cross-platform reference — they simply were not produced under the controlled, pinned, governor-fixed conditions that define the validator baseline. Read the Pi column as the controlled baseline and the M3 column as a cross-platform reference, and keep that distinction at every comparison (the column headers restate it).


## Key-encapsulation mechanisms

Timings are median ±MAD (adaptive µs/ms) with MAD as a percentage; sizes in bytes. **Cls** is the backend class (Ⓐ/Ⓑ/Ⓒ above); **Lvl** is the claimed NIST category. Each algorithm has one row per platform.

| Algorithm | Cls | Lvl | Platform | keygen | encaps | decaps | ct (B) | pk (B) | sk (B) |
|---|---|---|---|---|---|---|---|---|---|
| X25519 | · | 1 | RPi5 (cortex-a76, baseline) | 56.87 ±0.037 µs (0.1%) | — | — | — | 32 | 32 |
| X25519 | · | 1 | Apple M3 (apple-m3, cross-ref) | 44 ±0 µs (0.0%) | — | — | — | 32 | 32 |
| ML-KEM-512 | Ⓐ | 1 | RPi5 (cortex-a76, baseline) | 18.32 ±0.019 µs (0.1%) | 20.63 ±0.018 µs (0.1%) | 23.96 ±0.018 µs (0.1%) | 768 | 800 | 1632 |
| ML-KEM-512 | Ⓐ | 1 | Apple M3 (apple-m3, cross-ref) | 10 ±1 µs (10.0%) | 11 ±0 µs (0.0%) | 13 ±0 µs (0.0%) | 768 | 800 | 1632 |
| ML-KEM-768 | Ⓐ | 3 | RPi5 (cortex-a76, baseline) | 29.8 ±0.036 µs (0.1%) | 31.94 ±0.019 µs (0.1%) | 37.35 ±0.019 µs (0.1%) | 1088 | 1184 | 2400 |
| ML-KEM-768 | Ⓐ | 3 | Apple M3 (apple-m3, cross-ref) | 16 ±0 µs (0.0%) | 17 ±0 µs (0.0%) | 20 ±0 µs (0.0%) | 1088 | 1184 | 2400 |
| ML-KEM-1024 | Ⓐ | 5 | RPi5 (cortex-a76, baseline) | 44.02 ±0.037 µs (0.1%) | 47.61 ±0.019 µs (0.0%) | 55.31 ±0.019 µs (0.0%) | 1568 | 1568 | 3168 |
| ML-KEM-1024 | Ⓐ | 5 | Apple M3 (apple-m3, cross-ref) | 24 ±0 µs (0.0%) | 27 ±0 µs (0.0%) | 31 ±0 µs (0.0%) | 1568 | 1568 | 3168 |
| Classic-McEliece-348864 | Ⓒ | 1 | RPi5 (cortex-a76, baseline) | 149.1 ±70.64 ms (47.4%) | 66.04 ±0.407 µs (0.6%) | 25.69 ±0.002537 ms (0.0%) | 96 | 261120 | 6492 |
| Classic-McEliece-348864 | Ⓒ | 1 | Apple M3 (apple-m3, cross-ref) | 178.3 ±77.18 ms (43.3%) | 22 ±1 µs (4.5%) | 25.75 ±0.0135 ms (0.1%) | 96 | 261120 | 6492 |
| Classic-McEliece-460896 | Ⓒ | 3 | RPi5 (cortex-a76, baseline) | 346.6 ±115 ms (33.2%) | 130.8 ±11.19 µs (8.6%) | 58.76 ±0.2032 ms (0.3%) | 156 | 524160 | 13608 |
| Classic-McEliece-460896 | Ⓒ | 3 | Apple M3 (apple-m3, cross-ref) | 596.3 ±269.9 ms (45.3%) | 48 ±9 µs (18.8%) | 59.46 ±0.105 ms (0.2%) | 156 | 524160 | 13608 |
| Classic-McEliece-460896f | Ⓒ | 3 | RPi5 (cortex-a76, baseline) | 229.2 ±0.307 ms (0.1%) | 127.3 ±11.18 µs (8.8%) | 58.74 ±0.03799 ms (0.1%) | 156 | 524160 | 13608 |
| Classic-McEliece-460896f | Ⓒ | 3 | Apple M3 (apple-m3, cross-ref) | 342.7 ±1.163 ms (0.3%) | 48 ±9 µs (18.8%) | 59.6 ±0.132 ms (0.2%) | 156 | 524160 | 13608 |
| Classic-McEliece-6688128 | Ⓒ | 5 | RPi5 (cortex-a76, baseline) | 711.2 ±296.1 ms (41.6%) | 228.6 ±20.72 µs (9.1%) | 112.7 ±0.3154 ms (0.3%) | 208 | 1044992 | 13932 |
| Classic-McEliece-6688128 | Ⓒ | 5 | Apple M3 (apple-m3, cross-ref) | 2080 ±1335 ms (64.2%) | 120 ±25 µs (20.8%) | 114.5 ±0.203 ms (0.2%) | 208 | 1044992 | 13932 |
| Classic-McEliece-6960119 | Ⓒ | 5 | RPi5 (cortex-a76, baseline) | 718.9 ±300.1 ms (41.7%) | 356.7 ±15.13 µs (4.2%) | 109.1 ±0.4867 ms (0.4%) | 194 | 1047319 | 13948 |
| Classic-McEliece-6960119 | Ⓒ | 5 | Apple M3 (apple-m3, cross-ref) | 1283 ±612.8 ms (47.7%) | 158 ±12 µs (7.6%) | 110.8 ±0.321 ms (0.3%) | 194 | 1047319 | 13948 |
| Classic-McEliece-8192128 | Ⓒ | 5 | RPi5 (cortex-a76, baseline) | 812.5 ±364.4 ms (44.8%) | 260.9 ±16.36 µs (6.3%) | 136.6 ±0.2227 ms (0.2%) | 208 | 1357824 | 14120 |
| Classic-McEliece-8192128 | Ⓒ | 5 | Apple M3 (apple-m3, cross-ref) | 2501 ±1619 ms (64.8%) | 93 ±13 µs (14.0%) | 139.7 ±0.075 ms (0.1%) | 208 | 1357824 | 14120 |
| FrodoKEM-640-AES | Ⓒ | 1 | RPi5 (cortex-a76, baseline) | 786.3 ±0.379 µs (0.0%) | 923.2 ±0.222 µs (0.0%) | 901.2 ±0.185 µs (0.0%) | 9720 | 9616 | 19888 |
| FrodoKEM-640-AES | Ⓒ | 1 | Apple M3 (apple-m3, cross-ref) | 275 ±1 µs (0.4%) | 367 ±1 µs (0.3%) | 348 ±0 µs (0.0%) | 9720 | 9616 | 19888 |
| FrodoKEM-976-AES | Ⓒ | 3 | RPi5 (cortex-a76, baseline) | 1.691 ±0.002083 ms (0.1%) | 1.931 ±0.000982 ms (0.1%) | 1.882 ±0.000796 ms (0.0%) | 15744 | 15632 | 31296 |
| FrodoKEM-976-AES | Ⓒ | 3 | Apple M3 (apple-m3, cross-ref) | 541 ±1 µs (0.2%) | 718 ±1 µs (0.1%) | 682 ±3 µs (0.4%) | 15744 | 15632 | 31296 |
| FrodoKEM-1344-AES | Ⓒ | 5 | RPi5 (cortex-a76, baseline) | 3.07 ±0.000944 ms (0.0%) | 3.472 ±0.001305 ms (0.0%) | 3.409 ±0.001203 ms (0.0%) | 21632 | 21520 | 43088 |
| FrodoKEM-1344-AES | Ⓒ | 5 | Apple M3 (apple-m3, cross-ref) | 954 ±2 µs (0.2%) | 1.237 ±0.002 ms (0.2%) | 1.187 ±0.002 ms (0.2%) | 21632 | 21520 | 43088 |

The shape of the trade-off is visible directly. **ML-KEM** (Ⓐ) is compact and fast on both platforms — tens of microseconds, sub-1.6 kB keys and ciphertext. **Classic McEliece** (Ⓒ) inverts the profile: a *tiny* ciphertext (96–208 B, smaller than ML-KEM's) bought with an enormous public key (255 kB–1.33 MB) and a very slow keygen (hundreds of milliseconds to seconds), while encaps/decaps stay modest. **FrodoKEM** (Ⓒ), conservative unstructured LWE, is uniformly heavy: ~9.6–21 kB keys and ciphertext, and encaps/decaps in the hundreds of microseconds to low milliseconds. The `460896f` row is the fast-keygen variant of `460896`: identical sizes, materially faster and far more deterministic keygen (see the findings).


## Signatures

Same conventions; sizes are public-key, signature, and secret-key in bytes.

| Algorithm | Cls | Lvl | Platform | keygen | sign | verify | pk (B) | sig (B) | sk (B) |
|---|---|---|---|---|---|---|---|---|---|
| Ed25519 | · | 1 | RPi5 (cortex-a76, baseline) | 58.48 ±0.036 µs (0.1%) | 57.85 ±0.019 µs (0.0%) | 143.2 ±0.056 µs (0.0%) | 32 | 64 | 32 |
| Ed25519 | · | 1 | Apple M3 (apple-m3, cross-ref) | 45 ±0 µs (0.0%) | 45 ±0 µs (0.0%) | 125 ±1 µs (0.8%) | 32 | 64 | 32 |
| ML-DSA-44 | Ⓑ | 2 | RPi5 (cortex-a76, baseline) | 107.4 ±0.612 µs (0.6%) | 399.4 ±181.8 µs (45.5%) | 120.1 ±0.185 µs (0.2%) | 1312 | 2420 | 2560 |
| ML-DSA-44 | Ⓑ | 2 | Apple M3 (apple-m3, cross-ref) | 62 ±0 µs (0.0%) | 216 ±101 µs (46.8%) | 67 ±0 µs (0.0%) | 1312 | 2420 | 2560 |
| ML-DSA-65 | Ⓑ | 3 | RPi5 (cortex-a76, baseline) | 191.3 ±0.445 µs (0.2%) | 646.3 ±302.3 µs (46.8%) | 189 ±0.148 µs (0.1%) | 1952 | 3309 | 4032 |
| ML-DSA-65 | Ⓑ | 3 | Apple M3 (apple-m3, cross-ref) | 121 ±1 µs (0.8%) | 375 ±144 µs (38.4%) | 109 ±0 µs (0.0%) | 1952 | 3309 | 4032 |
| ML-DSA-87 | Ⓑ | 5 | RPi5 (cortex-a76, baseline) | 288.4 ±1.148 µs (0.4%) | 836.6 ±346.7 µs (41.4%) | 308.8 ±0.555 µs (0.2%) | 2592 | 4627 | 4896 |
| ML-DSA-87 | Ⓑ | 5 | Apple M3 (apple-m3, cross-ref) | 172 ±1 µs (0.6%) | 475 ±206 µs (43.4%) | 181 ±0 µs (0.0%) | 2592 | 4627 | 4896 |
| Falcon-512 | Ⓐ | 1 | RPi5 (cortex-a76, baseline) | 8.913 ±1.152 ms (12.9%) | 290.1 ±2.222 µs (0.8%) | 50.72 ±0.074 µs (0.1%) | 897 | 752 | 1281 |
| Falcon-512 | Ⓐ | 1 | Apple M3 (apple-m3, cross-ref) | 6.422 ±0.708 ms (11.0%) | 204 ±2 µs (1.0%) | 31 ±0 µs (0.0%) | 897 | 752 | 1281 |
| Falcon-1024 | Ⓐ | 5 | RPi5 (cortex-a76, baseline) | 26.16 ±2.447 ms (9.4%) | 592 ±2.981 µs (0.5%) | 99.83 ±0.148 µs (0.1%) | 1793 | 1462 | 2305 |
| Falcon-1024 | Ⓐ | 5 | Apple M3 (apple-m3, cross-ref) | 20.4 ±1.065 ms (5.2%) | 410 ±4 µs (1.0%) | 62 ±0 µs (0.0%) | 1793 | 1462 | 2305 |
| SPHINCS+-SHA2-128f-simple | Ⓑ | 1 | RPi5 (cortex-a76, baseline) | 1.564 ±0.002509 ms (0.2%) | 36.45 ±0.02847 ms (0.1%) | 2.266 ±0.001463 ms (0.1%) | 32 | 17088 | 64 |
| SPHINCS+-SHA2-128f-simple | Ⓑ | 1 | Apple M3 (apple-m3, cross-ref) | 861 ±3 µs (0.3%) | 20.24 ±0.0955 ms (0.5%) | 1.246 ±0.007 ms (0.6%) | 32 | 17088 | 64 |
| SPHINCS+-SHA2-128s-simple | Ⓑ | 1 | RPi5 (cortex-a76, baseline) | 96.99 ±0.1599 ms (0.2%) | 734.1 ±0.7932 ms (0.1%) | 728.2 ±0.445 µs (0.1%) | 32 | 7856 | 64 |
| SPHINCS+-SHA2-128s-simple | Ⓑ | 1 | Apple M3 (apple-m3, cross-ref) | 55.33 ±0.1745 ms (0.3%) | 422.5 ±1.496 ms (0.4%) | 414 ±1 µs (0.2%) | 32 | 7856 | 64 |
| SPHINCS+-SHA2-192f-simple | Ⓑ | 3 | RPi5 (cortex-a76, baseline) | 2.394 ±0.001907 ms (0.1%) | 64 ±0.06017 ms (0.1%) | 3.336 ±0.001205 ms (0.0%) | 48 | 35664 | 96 |
| SPHINCS+-SHA2-192f-simple | Ⓑ | 3 | Apple M3 (apple-m3, cross-ref) | 1.252 ±0.005 ms (0.4%) | 33.45 ±0.2045 ms (0.6%) | 1.853 ±0.014 ms (0.8%) | 48 | 35664 | 96 |
| SPHINCS+-SHA2-256f-simple | Ⓑ | 5 | RPi5 (cortex-a76, baseline) | 6.309 ±0.003704 ms (0.1%) | 132.5 ±0.09963 ms (0.1%) | 3.558 ±0.001582 ms (0.0%) | 64 | 49856 | 128 |
| SPHINCS+-SHA2-256f-simple | Ⓑ | 5 | Apple M3 (apple-m3, cross-ref) | 3.352 ±0.012 ms (0.4%) | 69 ±0.289 ms (0.4%) | 1.9 ±0.007 ms (0.4%) | 64 | 49856 | 128 |

**ML-DSA** (Ⓑ) is the balanced lattice signature: fast sign/verify (hundreds of microseconds) with mid-kilobyte keys and signatures. Its `sign` MAD is high (~40–47%) on both platforms — ML-DSA uses rejection sampling in signing, so the per-signature time genuinely varies; that noise is real and shown, not smoothed. **Falcon** (Ⓐ) verifies very fast and signs quickly, but note the heavy, variable keygen (8.9 ms / 26 ms on the Pi) from its NTRU lattice / FFT sampling. **SLH-DSA / SPHINCS+** (Ⓑ) is the hash-based, conservative option: small keys (32–64 B public) but large signatures (7.9–49.9 kB) and slow signing — the `128s` 'small-signature' variant signs in ~0.4–0.7 s, the `f` 'fast' variants in tens of milliseconds. These hash-heavy schemes are where the M3's hardware SHA3 matters (findings).


## TLS 1.3 handshakes

Full TLS 1.3 handshakes over in-process memory BIOs (KEM key-exchange group × PQ server-auth signature), via OpenSSL 3.x with oqs-provider. The classical **X25519 + Ed25519** pair is measured on both platforms as the reference line, so each PQ row reads as a delta against classical rather than in isolation. `hs/s` is handshakes per second (higher is better); latency is the median handshake time in milliseconds.

| Group / label | RPi5 hs/s | RPi5 lat (ms) | M3 hs/s | M3 lat (ms) |
|---|---|---|---|---|
| X25519+ed25519  ← classical baseline | 755.4 | 1.324 | 1401 | 0.714 |
| X25519MLKEM768+mldsa44 | 374.2 | 2.672 | 841.8 | 1.188 |
| X25519MLKEM768+mldsa65 | 274.8 | 3.64 | 663.3 | 1.508 |
| X25519MLKEM768+mldsa87 | 236.9 | 4.222 | 537.1 | 1.862 |
| X25519MLKEM768+falcon512 | 310.2 | 3.224 | 598.3 | 1.671 |
| X25519MLKEM768+sphincssha2128fsimple | 22.7 | 44.12 | 40.2 | 24.89 |
| SecP256r1MLKEM768+mldsa44 | 369.2 | 2.709 | 862.8 | 1.159 |
| SecP256r1MLKEM768+mldsa65 | 275.3 | 3.633 | 647.2 | 1.545 |
| SecP256r1MLKEM768+mldsa87 | 234.1 | 4.271 | 543.8 | 1.839 |
| SecP256r1MLKEM768+falcon512 | 294.2 | 3.399 | 604.6 | 1.654 |
| SecP256r1MLKEM768+sphincssha2128fsimple | 22.7 | 44.09 | 40.7 | 24.57 |
| mlkem512+mldsa44 | 477.6 | 2.094 | 1068 | 0.936 |
| mlkem512+mldsa65 | 365.9 | 2.733 | 794.9 | 1.258 |
| mlkem512+mldsa87 | 274.3 | 3.646 | 620.3 | 1.612 |
| mlkem512+falcon512 | 386.5 | 2.587 | 703.7 | 1.421 |
| mlkem512+sphincssha2128fsimple | 23.2 | 43.18 | 40.8 | 24.52 |
| mlkem768+mldsa44 | 451.6 | 2.215 | 1030 | 0.971 |
| mlkem768+mldsa65 | 323.7 | 3.09 | 734.2 | 1.362 |
| mlkem768+mldsa87 | 266.9 | 3.747 | 603.1 | 1.658 |
| mlkem768+falcon512 | 349.4 | 2.862 | 678.4 | 1.474 |
| mlkem768+sphincssha2128fsimple | 23 | 43.54 | 40.6 | 24.6 |
| mlkem1024+mldsa44 | 432.7 | 2.311 | 957.4 | 1.044 |
| mlkem1024+mldsa65 | 310.5 | 3.22 | 698.3 | 1.432 |
| mlkem1024+mldsa87 | 259 | 3.861 | 578 | 1.73 |
| mlkem1024+falcon512 | 357.4 | 2.798 | 646.8 | 1.546 |
| mlkem1024+sphincssha2128fsimple | 21.8 | 45.82 | 40.4 | 24.77 |

Against the classical baseline (Pi 755 hs/s; M3 1401 hs/s), the ML-KEM / hybrid key-exchange groups paired with ML-DSA cost roughly 1.5–3× in handshake throughput on the Pi and ~1.3–1.7× on the M3 — a modest, practical overhead. The outlier is any cell using an **SLH-DSA (SPHINCS+)** certificate: its multi-kilobyte signature collapses throughput to ~22 hs/s on the Pi and ~40 hs/s on the M3 (handshake latency ~24–46 ms), which is the dominant cost in the handshake and the reason SLH-DSA is a fallback rather than a default for interactive TLS. Key-exchange group choice (ML-KEM-512/768/1024, X25519- vs SecP256r1-hybrid) moves throughput far less than signature choice does.


## Cross-platform findings

**Tuned crypto (Ⓐ) — the M3 leads by ~1.5–1.9×.** With a dedicated aarch64 assembly backend on both sides, raw core advantage shows cleanly. ML-KEM keygen is 1.83× faster / 1.86× faster / 1.83× faster (512/768/1024) on the M3 versus the A76; Falcon-512 signs 1.42× faster and verifies 1.64× faster. These are optimised-vs-optimised, so the gap is essentially microarchitecture and clock.

**Hash-heavy schemes (Ⓑ) — the M3 also leads, ~1.7–1.8×, but partly for a different reason.** ML-DSA-65 signs 1.72× faster and verifies 1.73× faster; SLH-DSA/SPHINCS+ signs 1.80× faster (128f) / 1.74× faster (128s). Neither has a dedicated arithmetic asm backend, so this is **not** an asm effect. Two factors contribute: the M3's faster cores, and its hardware **SHA3** instruction (`OQS_USE_ARM_SHA3_INSTRUCTIONS`), which the Cortex-A76 does not have — on the A76 the Keccak permutation that dominates these schemes runs on NEON/scalar code instead. These two contributions cannot be cleanly separated from this data; both are present and the split is not isolated here. The point is only that the Ⓑ lead is core-speed *plus* a hashing-instruction edge, not a tuned backend.

**Classic McEliece keygen (Ⓒ) — the notable inversion: the M3 is ~1.5× *slower*.** On the deterministic `460896f` variant — which has near-zero MAD on both platforms (0.1% Pi, 0.3% M3), so the comparison is clean — McEliece keygen is 1.50× **slower** on the M3 than on the A76 (229.2 ms vs 342.7 ms). The non-`f` variants corroborate the same direction but noisily: their keygen uses rejection sampling (retry until the matrix inverts), giving 33–65% MAD on both platforms, so their medians swing — which is exactly why the deterministic `f` variant is the right anchor.

**Why this is a real architecture effect, not a measurement artifact.** The slowdown is **keygen-specific**: on the same McEliece-460896 parameter set the M3 is actually *faster* on encaps (2.72×) and essentially *tied* on decaps (58.76 ms on the Pi vs 59.46 ms on the M3, within ~1%) — it is materially slower *only* on keygen. And on the very same unpinned M3 run, two entirely different backend classes win comfortably — Ⓐ ML-KEM (~1.8×) and Ⓑ ML-DSA (~1.7×). A pinning- or governor-related handicap would drag everything down uniformly; instead the M3 loses on exactly one workload while winning on others. That localises the effect to the McEliece keygen itself.

**Hypothesis (labelled as such).** Classic McEliece keygen is dominated by Gaussian elimination over GF(2^m) on a very large matrix — branchy, memory-bandwidth-bound, scalar portable-C with no vectorised backend on either platform. A plausible explanation is that the Cortex-A76's memory subsystem / cache behaviour suits this access pattern better than the M3's does for this particular portable-C code, or that the compiler's codegen for it favours the A76. This is a hypothesis consistent with the data, not a measured conclusion; isolating it would need cycle-level profiling of the keygen inner loop.


> Backend legend — Ⓐ asm (dedicated aarch64 backend, both platforms: ML-KEM, Falcon) · Ⓑ portable-C + hardware hash (ML-DSA, SLH-DSA; Keccak/SHA-2 via HW instructions, M3 additionally has HW SHA3, the A76 does not) · Ⓒ portable-C (Classic McEliece, FrodoKEM; Frodo-AES uses HW AES on both, McEliece none) · · classical reference via OpenSSL.


## Provenance

Each result file is self-describing; the fields that matter for reading these numbers are reproduced below verbatim from the JSONs.

| Run | cpu_brand | cflags_target | bench_cflags | liboqs_commit | baseline_grade | cycles_avail | generated_utc |
|---|---|---|---|---|---|---|---|
| Pi KEM/sig | Raspberry Pi 5 Model B Rev 1.1 | cortex-a76 | -O3 -mcpu=cortex-a76 | 97f6b86b1b6d | True | False | 2026-06-14T21:09:20Z |
| Pi TLS | Raspberry Pi 5 Model B Rev 1.1 | cortex-a76 | -O3 -mcpu=cortex-a76 | 97f6b86b1b6d | True | False | 2026-06-08T22:39:28Z |
| M3 KEM/sig | Apple M3 | apple-m3 | -O3 -mcpu=native | 97f6b86b1b6d | False | False | 2026-06-24T14:29:31Z |
| M3 TLS | Apple M3 | apple-m3 | -O3 -mcpu=native | 97f6b86b1b6d | False | False | 2026-06-24T20:17:12Z |

liboqs commit `97f6b86…` is identical across all four runs; the only toolchain difference is the target flags (`cortex-a76` vs `apple-m3`). oqs-provider 0.9.0 (`848b4e6…`) backs both TLS runs. Source files: `rasberrypi5-20260614T205226Z.json` (Pi KEM/sig), `rasberrypi5-20260608T223040Z.json` (Pi TLS), `mehmetmac-20260624T140033Z.json` (M3 KEM/sig), `mehmetmac-20260624T201430Z.json` (M3 TLS).


*(An interactive ratio chart is included in the HTML version; see the Cross-platform findings table for the underlying values.)*


> Chart values are the same medians as the tables (RPi5 median ÷ M3 median); ratios >1 mean the M3 is faster. The single bar left of the line is McEliece keygen.

