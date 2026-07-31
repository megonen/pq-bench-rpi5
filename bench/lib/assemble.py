#!/usr/bin/env python3
"""assemble.py — merge harness outputs + thermal trace + environment metadata
into one results JSON with full provenance.

Inputs (all paths):
  --meta      meta.env       KEY=VALUE run/host facts collected by run.sh
  --lock      versions.lock  toolchain provenance from setup.sh
  --features  cpu_features.json  CPU/crypto-extension detection (from run.sh)
  --kemsig    kemsig.jsonl   one JSON object per algorithm from bench_pq
  --tls       tls.json       output of the TLS harness (optional)
  --thermal   thermal.csv    epoch_s,arm_clock_hz,temp_c,throttled_hex samples
  --out       results/<host>-<ts>.json

The single most important output field is `is_baseline_grade`: true ONLY on a
real RPi5 with performance governor, core pinning, A76-targeted flags, and no
thermal throttling. Everything else (notably macOS smoke runs) is false, with
reasons recorded — so smoke output can never be mistaken for the baseline.
"""
from __future__ import annotations
import argparse
import json
import os
import statistics
import sys

# 2.0.0: per-row `backend` renamed to `implementation` (which library produced
# the measurement — vocabulary: liboqs, openssl, rustcrypto, oqs-provider,
# openssl-native, rustls-awslc); KEM/sig rows gained a `total` aggregate; TLS
# matrix cells gained `phase` / `implementation` / `sig_alg` and a
# `handshake_primitive_sum` block relating handshake latency to the primitive
# operations it performs.
SCHEMA_VERSION = "2.0.0"

# Shared honesty note for every aggregate we compute from per-op medians.
DERIVED_NOTE = ("sum of per-operation medians; a derived figure "
                "(a sum of medians is not the median of a sum), "
                "not a measured latency")


def parse_envfile(path: str) -> dict:
    """Parse KEY=VALUE / KEY="value" lines (shared format of meta.env + versions.lock)."""
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k.strip()] = v
    return out


def load_jsonl(path: str) -> list:
    items = []
    if not path or not os.path.exists(path):
        return items
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[assemble] skipping bad JSONL line: {e}", file=sys.stderr)
    return items


def load_json(path: str):
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def parse_thermal(path: str) -> dict:
    """Reduce the raw CSV trace to a compact embedded record + summary."""
    cols = ["epoch_s", "arm_clock_hz", "temp_c", "throttled_hex"]
    samples, temps, clocks = [], [], []
    throttling_detected = False
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) != 4:
                    continue
                ep, clk, temp, thr = parts
                samples.append([
                    int(ep) if ep else None,
                    int(clk) if clk else None,
                    float(temp) if temp else None,
                    thr or None,
                ])
                if temp:
                    temps.append(float(temp))
                if clk:
                    clocks.append(int(clk))
                if thr:
                    try:
                        v = int(thr, 16)
                        # bit2 = throttling now, bit18 = throttling has occurred
                        if v & 0x4 or v & 0x40000:
                            throttling_detected = True
                    except ValueError:
                        pass

    def summarize(vals):
        if not vals:
            return None
        return {
            "min": min(vals), "max": max(vals),
            "mean": round(statistics.fmean(vals), 3),
            "samples": len(vals),
        }

    clock_summary = summarize(clocks)
    # Detect frequency droop as a secondary throttling signal.
    if clock_summary and clocks:
        spread = (max(clocks) - min(clocks)) / max(clocks)
        clock_summary["spread_frac"] = round(spread, 4)

    return {
        "columns": cols,
        "samples": samples,
        "temp_c": summarize(temps),
        "arm_clock_hz": clock_summary,
        "throttling_detected": throttling_detected,
    }


def to_int(s, default=None):
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


# ---- schema v2 helpers ------------------------------------------------------

def normalize_kemsig_row(row: dict) -> dict:
    """v1 compat: rows emitted by pre-2.0 harness builds carry `backend`; the
    field is now `implementation` (same meaning). Lets assemble re-run on old
    work dirs without rewriting them."""
    if "implementation" not in row and "backend" in row:
        row["implementation"] = row.pop("backend")
    return row


# The canonical one-full-cycle operations per row kind. Auxiliary operations
# (e.g. the rustcrypto rows' `verify_cached_key` variant) are deliberately NOT
# part of the total — the cycle contains one verify, priced at the wire-bytes
# (`verify`) shape.
TOTAL_OPS = ("keygen", "encaps", "decaps", "derive", "sign", "verify")


def add_row_total(row: dict) -> None:
    """Aggregate one row's full operation cycle (KEM: keygen+encaps+decaps;
    sig: keygen+sign+verify; the X25519 KEM-analog: keygen+derive)."""
    ops = row.get("operations") or {}
    medians = {op: (st or {}).get("median")
               for op, st in ops.items() if op in TOTAL_OPS}
    if not medians or any(v is None for v in medians.values()):
        return
    row["total"] = {
        "sum_of_medians_ns": round(sum(medians.values()), 2),
        "operations": list(medians.keys()),
        "note": DERIVED_NOTE,
    }


def norm_alg(name: str) -> str:
    """Case/punctuation-insensitive algorithm key: 'ML-DSA-44' -> 'mldsa44',
    'SPHINCS+-SHA2-128f-simple' -> 'sphincssha2128fsimple' (the oqs-provider
    spelling), so TLS names and primitive names meet without a lookup table."""
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


PQ_KEM_TOKENS = ("mlkem", "kyber", "frodo", "hqc", "bike", "ntru", "mceliece")
CLASSICAL_SIG_PREFIXES = ("ed25519", "ed448", "ecdsa", "rsa")


def infer_phase(group: str, sig_alg: str) -> str:
    """Migration-framework phase of a TLS cell (fallback for rows produced
    before the harness emitted `phase` itself; keep in sync with
    bench/tls/run_tls.sh phase_for())."""
    g, s = (group or "").lower(), (sig_alg or "").lower()
    pq_kem = any(t in g for t in PQ_KEM_TOKENS)
    classical_sig = s.startswith(CLASSICAL_SIG_PREFIXES)
    if classical_sig:
        return "phase0" if pq_kem else "baseline"
    return "phase2"


# Primitive operations one TLS 1.3 handshake performs, per component.
# KEM framing: client generates the keyshare (keygen), server encapsulates,
# client decapsulates. ECDH framing (X25519 rows measure keygen+derive): both
# sides generate a keyshare and both sides derive, hence count 2 + 2.
KEM_OPS = (("keygen", 1, "client KEM keyshare generation"),
           ("encaps", 1, "server encapsulation"),
           ("decaps", 1, "client decapsulation"))
ECDH_OPS = (("keygen", 2, "client + server ECDH keyshare generation"),
            ("derive", 2, "shared-secret derivation on both sides"))
SIG_OPS = (("sign", 1, "server CertificateVerify signature"),
           ("verify", 2, "client verifies CertificateVerify + the CA signature "
                         "over the server certificate"))

HANDSHAKE_SUM_NOTE = (
    "sum over the primitive operations one TLS 1.3 handshake performs with "
    "this configuration, priced at the per-operation medians from this run's "
    "KEM/sig sweep. Derived, not measured (" + DERIVED_NOTE + "); excludes "
    "KDF/record-layer/X.509-parsing and all protocol overhead — the gap to "
    "handshake_latency_ns.median is exactly that overhead. verify count 2 "
    "assumes the client checks the CertificateVerify and the CA signature on "
    "the leaf certificate (OpenSSL does not verify the trust anchor's "
    "self-signature by default).")


def kem_group_components(group: str):
    """Map a TLS group to its measured KEM-side components.
    Returns ([(normalized_alg, ops_spec), ...], [missing_descriptions])."""
    g = norm_alg(group)
    if g == "x25519":
        return [("x25519", ECDH_OPS)], []
    if g in ("mlkem512", "mlkem768", "mlkem1024"):
        return [(g, KEM_OPS)], []
    if g == "x25519mlkem768":
        return [("x25519", ECDH_OPS), ("mlkem768", KEM_OPS)], []
    if g == "x448mlkem1024":
        return [("x448", ECDH_OPS), ("mlkem1024", KEM_OPS)], []
    if g == "secp256r1mlkem768":
        return [("secp256r1", ECDH_OPS), ("mlkem768", KEM_OPS)], []
    if g == "secp384r1mlkem1024":
        return [("secp384r1", ECDH_OPS), ("mlkem1024", KEM_OPS)], []
    return [], [f"no primitive mapping defined for TLS group '{group}'"]


# ---- acceleration provenance (per-row, empirically determined) -------------
# Two independent axes, recorded in the JSON so the companion document's
# classification cannot drift from reality:
#   arithmetic — hand-written asm vs portable code (derived from build
#     provenance: liboqs' *_aarch64 enable defines / the Rust provenance).
#   symmetric  — which primitive(s) the hot loop uses, where that
#     implementation comes from, and whether it reaches hardware instructions
#     on this CPU (combined with the run's cpu_features).
# Sources for liboqs rows were established by DIFFERENTIAL BUILDS on
# 2026-07-19/20 (liboqs 0.15.0 @97f6b86, Apple M3): toggling
# OQS_USE_{SHA2,AES,SHA3}_OPENSSL and measuring which rows move. Key results:
#   SPHINCS+-SHA2  moved ~54%  when SHA-2 left OpenSSL  -> OQS SHA-2 layer (EVP)
#   SLH-DSA        moved 0%    on every toggle          -> bundles its own
#                  portable SHA-2/SHA-3 (verified in slh_dsa_c source)
#   FrodoKEM-AES   moved 8-13% when AES left OpenSSL    -> OQS AES layer (EVP)
#   ML-KEM         moved 15-24% when SHA-3 moved to EVP -> OQS SHA-3 layer
#                  (liboqs-internal xkcp in the shipped config)
#   ML-DSA/Falcon  <=2% on the SHA-3 toggle (differential inconclusive); the
#                  pqclean fips202 shim routes them to the OQS SHA-3 layer
#                  (source inspection), their dominant SHAKE path is simply
#                  insensitive to the toggle.
#   McEliece       encaps/decaps flat on every toggle; keygen medians too
#                  unstable (rejection sampling) for the differential to
#                  resolve — SHAKE via the fips202 shim per source inspection.

DIFF = "differential-build"
SRC_INSP = "source-inspection"


def _sym(primitive, source, hw, determined_by, note=None):
    d = {"primitive": primitive, "source": source,
         "hw_instructions": bool(hw), "determined_by": determined_by}
    if note:
        d["note"] = note
    return d


def acceleration_for(row: dict, features: dict, opt_defines: str,
                     rust_prov: dict) -> dict:
    impl = row.get("implementation")
    n = norm_alg(row.get("alg"))
    aes_hw = features.get("aes")
    sha2_hw = features.get("sha2")
    sha3_hw = features.get("sha3")

    if impl == "openssl":  # classical EVP baselines
        return {"arithmetic": {"path": "openssl-internal",
                               "detail": "OpenSSL's own curve25519 code (assembly on major targets)"},
                "symmetric": [],
                "determined_by": SRC_INSP}

    if impl == "aws-lc-rs":  # pricing rows for the rustls-awslc TLS group
        return {"arithmetic": {
                    "path": "aws-lc-native",
                    "detail": "AWS-LC C/assembly via the aws-lc-rs FFI wrapper — "
                              "measured to price rustls-awslc handshakes, NOT an "
                              "independent implementation"},
                "symmetric": [
                    {"primitive": "internal", "source": "AWS-LC internal",
                     "hw_instructions": None,
                     "determined_by": "not separately characterised"}],
                "determined_by": SRC_INSP}

    if impl == "rustcrypto":
        arith = {"path": "portable-rust",
                 "detail": "no hand-written asm / explicit SIMD; compiler autovectorisation only"}
        if n in ("x25519", "ed25519"):
            arith["detail"] = "curve25519-dalek (portable Rust with formally-derived field arithmetic)"
            sym = []
        elif n.startswith("mlkem") or n.startswith("mldsa"):
            sym = [_sym("sha3-shake", "rust keccak crate (cpufeatures runtime dispatch)",
                        sha3_hw, SRC_INSP,
                        "reaches ARMv8.2 SHA3 instructions only where the CPU has them "
                        "(Apple M-series yes, Cortex-A76 no)")]
        elif "slhdsa" in n or "sha2" in n:
            sym = [_sym("sha2", "rust sha2 crate (cpufeatures runtime dispatch)",
                        sha2_hw, SRC_INSP)]
        else:
            sym = []
        return {"arithmetic": arith, "symmetric": sym, "determined_by": SRC_INSP}

    # ---- liboqs rows --------------------------------------------------------
    defines = opt_defines or ""

    def asm_enabled(token):
        return f"{token} 1" in defines

    arith = {"path": "portable-c"}
    if n.startswith("mlkem"):
        size = n.replace("mlkem", "")
        if asm_enabled(f"OQS_ENABLE_KEM_ml_kem_{size}_aarch64"):
            arith = {"path": "aarch64-asm", "detail": "mlkem-native aarch64 backend"}
        sym = [_sym("sha3-shake", "OQS SHA-3 layer (liboqs-internal xkcp)", sha3_hw,
                    DIFF + " (+15-24% when redirected to OpenSSL EVP)")]
    elif n.startswith("falcon"):
        size = "512" if "512" in n else "1024"
        if asm_enabled(f"OQS_ENABLE_SIG_falcon_{size}_aarch64"):
            arith = {"path": "aarch64-asm", "detail": "falcon aarch64 backend"}
        sym = [_sym("sha3-shake", "OQS SHA-3 layer (liboqs-internal xkcp)", sha3_hw,
                    SRC_INSP + " (fips202 shim; differential <=2% — minor SHAKE share)")]
    elif n.startswith("mldsa"):
        sym = [_sym("sha3-shake", "OQS SHA-3 layer (liboqs-internal xkcp)", sha3_hw,
                    SRC_INSP + " (fips202 shim; differential inconclusive at <=2%)")]
    elif n.startswith("slhdsa"):
        prim = "sha2" if "sha2" in n else "sha3-shake"
        sym = [_sym(prim, "bundled portable C inside slh_dsa_c (ignores the OQS symmetric layers)",
                    False, DIFF + " (0% on every toggle) + " + SRC_INSP)]
    elif n.startswith("sphincs"):
        prim = "sha2" if "sha2" in n else "sha3-shake"
        src = "OQS SHA-2 layer (OpenSSL EVP)" if prim == "sha2" \
            else "OQS SHA-3 layer (liboqs-internal xkcp)"
        hw = sha2_hw if prim == "sha2" else sha3_hw
        det = DIFF + " (~54% slower with liboqs-internal SHA-2)" if prim == "sha2" else SRC_INSP
        sym = [_sym(prim, src, hw, det)]
    elif n.startswith("frodokem"):
        sym = [_sym("aes", "OQS AES layer (OpenSSL EVP)", aes_hw,
                    DIFF + " (+8-13% with liboqs-internal AES)")]
        if "shake" in n:
            sym = [_sym("sha3-shake", "OQS SHA-3 layer (liboqs-internal xkcp)", sha3_hw, SRC_INSP)]
    elif n.startswith("classicmceliece"):
        sym = [_sym("sha3-shake", "fips202 shim -> OQS SHA-3 layer", sha3_hw,
                    SRC_INSP + " (differential flat on encaps/decaps; keygen medians "
                    "too unstable — rejection sampling — to resolve)")]
    else:
        sym = []
    return {"arithmetic": arith, "symmetric": sym,
            "determined_by": "; ".join(sorted({s["determined_by"].split(" (")[0] for s in sym}) or [SRC_INSP])}


def annotate_acceleration(kem_rows, sig_rows, features, opt_defines, rust_prov):
    for row in kem_rows + sig_rows:
        if row.get("enabled"):
            row["acceleration"] = acceleration_for(row, features or {},
                                                   opt_defines, rust_prov or {})


def cross_check_sizes(kem_rows: list, sig_rows: list, warnings: list) -> None:
    """When the same algorithm is measured by more than one implementation
    (liboqs vs rustcrypto), their reported sizes MUST agree on every field
    they both carry — a mismatch means a bug or a spec disagreement, not a
    benchmarking result. Reported loudly: warnings array + stderr."""
    for rows in (kem_rows, sig_rows):
        by_alg = {}
        for r in rows:
            if r.get("enabled"):
                by_alg.setdefault(norm_alg(r.get("alg")), []).append(r)
        for group in by_alg.values():
            base = group[0]
            bs = base.get("sizes") or {}
            for other in group[1:]:
                os_ = other.get("sizes") or {}
                for key in sorted(set(bs) & set(os_)):
                    if bs[key] != os_[key]:
                        msg = (f"SIZE MISMATCH for {base['alg']} .{key}: "
                               f"{base.get('implementation')}={bs[key]} vs "
                               f"{other.get('implementation')}={os_[key]} — "
                               "bug or spec disagreement, NOT a benchmark result")
                        warnings.append(msg)
                        print(f"[assemble] {msg}", file=sys.stderr)


def annotate_tls(tls: dict, kem_rows: list, sig_rows: list) -> None:
    """Stamp phase/implementation/sig_alg defaults and compute the
    handshake_primitive_sum block for every enabled matrix cell."""
    # Sums must be priced from the primitives the handshake ACTUALLY executes:
    # C-stack cells (openssl-native / oqs-provider) strictly from liboqs and
    # openssl rows; rustls-awslc cells strictly from aws-lc-rs rows. A row
    # from the wrong implementation (e.g. pure-Rust rustcrypto, ~2x slower
    # than the asm paths) must NEVER price a cell, even when it is the only
    # row with a matching algorithm name.
    idx_c, idx_awslc = {}, {}
    for row in kem_rows + sig_rows:
        if not row.get("enabled"):
            continue
        key = (row.get("kind"), norm_alg(row.get("alg")))
        impl = row.get("implementation")
        if impl in ("liboqs", "openssl"):
            idx_c.setdefault(key, row)
        elif impl == "aws-lc-rs":
            idx_awslc.setdefault(key, row)

    def component_entries(kind, row, ops_spec, out, missing):
        for op, count, role in ops_spec:
            st = (row.get("operations") or {}).get(op) or {}
            med = st.get("median")
            if med is None:
                missing.append(
                    f"operation '{op}' not measured for {kind} primitive "
                    f"'{row.get('alg')}'")
                continue
            out.append({
                "kind": kind, "alg": row.get("alg"),
                "implementation": row.get("implementation"),
                "operation": op, "count": count,
                "median_ns_each": med,
                "subtotal_ns": round(count * med, 2),
                "role": role,
            })

    for cell in (tls.get("matrix") or []):
        label = cell.get("label") or ""
        sig_alg = cell.get("sig_alg") or \
            (label.split("+", 1)[1] if "+" in label else "")
        cell["sig_alg"] = sig_alg
        cell.setdefault("implementation", "oqs-provider")
        if not cell.get("phase"):
            cell["phase"] = infer_phase(cell.get("group"), sig_alg)
        if not cell.get("enabled"):
            continue

        if cell.get("implementation") == "rustls-awslc":
            idx, stack = idx_awslc, "aws-lc-rs"
        else:
            idx, stack = idx_c, "liboqs/openssl"

        comps_spec, missing = kem_group_components(cell.get("group"))
        components = []
        for alg_key, ops_spec in comps_spec:
            row = idx.get(("kem", alg_key))
            if row is None:
                missing.append(
                    f"KEM primitive matching '{alg_key}' not measured from the "
                    f"{stack} implementation in this run")
                continue
            component_entries("kem", row, ops_spec, components, missing)
        srow = idx.get(("sig", norm_alg(sig_alg)))
        if srow is None:
            missing.append(
                f"signature primitive matching '{sig_alg}' not measured from "
                f"the {stack} implementation in this run")
        else:
            component_entries("sig", srow, SIG_OPS, components, missing)

        complete = not missing
        cell["handshake_primitive_sum"] = {
            "sum_of_medians_ns":
                round(sum(c["subtotal_ns"] for c in components), 1)
                if complete else None,
            "complete": complete,
            "components": components,
            "missing": missing,
            "note": HANDSHAKE_SUM_NOTE,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--meta", required=True)
    ap.add_argument("--lock", default="")
    ap.add_argument("--features", default="")
    ap.add_argument("--kemsig", default="")
    ap.add_argument("--tls", default="")
    ap.add_argument("--rust-provenance", default="",
                    help="JSON from pqb-rust --provenance (or an "
                         "available:false stub explaining why the rustcrypto "
                         "group did not run)")
    ap.add_argument("--rust-tls-provenance", default="",
                    help="JSON from pqb-rust-tls --provenance (the "
                         "rustls-awslc TLS group)")
    ap.add_argument("--thermal", default="")
    ap.add_argument("--config", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    meta = parse_envfile(args.meta)
    lock = parse_envfile(args.lock)
    features = load_json(args.features) or {}
    kemsig = [normalize_kemsig_row(r) for r in load_jsonl(args.kemsig)]
    tls = load_json(args.tls)
    thermal = parse_thermal(args.thermal)

    rust_toolchain = load_json(args.rust_provenance) or {
        "available": False, "reason": "rust harness not run"}
    rust_tls_toolchain = load_json(args.rust_tls_provenance) or {
        "available": False, "reason": "rustls harness not run"}

    for row in kemsig:
        if row.get("enabled"):
            add_row_total(row)
    kem_rows = [r for r in kemsig if r.get("kind") == "kem"]
    sig_rows = [r for r in kemsig if r.get("kind") == "sig"]
    annotate_acceleration(kem_rows, sig_rows, features,
                          lock.get("LIBOQS_OPT_DEFINES", ""), rust_toolchain)
    if isinstance(tls, dict):
        annotate_tls(tls, kem_rows, sig_rows)

    is_rpi = meta.get("IS_RPI") == "1"
    governor = meta.get("GOVERNOR_AFTER") or meta.get("GOVERNOR_BEFORE") or "unknown"
    pinned = meta.get("PINNED") == "1"
    cflags_target = lock.get("CFLAGS_TARGET", "unknown")

    # ---- the anti-confusion gate -----------------------------------------
    baseline_reasons = []
    if not is_rpi:
        baseline_reasons.append(
            f"host is not a Raspberry Pi (model='{meta.get('RPI_MODEL','')}', os={meta.get('OS')})")
    if governor != "performance":
        baseline_reasons.append(f"CPU governor is '{governor}', not 'performance'")
    if not pinned:
        baseline_reasons.append("benchmark was not pinned to a dedicated core (no taskset)")
    if cflags_target != "cortex-a76":
        baseline_reasons.append(f"build flags targeted '{cflags_target}', not cortex-a76")
    if thermal.get("throttling_detected"):
        baseline_reasons.append("thermal throttling was detected during the run")
    is_baseline_grade = len(baseline_reasons) == 0

    warnings = []
    raw_warn = meta.get("WARNINGS", "")
    if raw_warn:
        warnings.extend([w for w in raw_warn.split("||") if w])
    if not is_baseline_grade:
        warnings.append("NOT RPi5-baseline-grade: " + "; ".join(baseline_reasons))
    cross_check_sizes(kem_rows, sig_rows, warnings)

    result = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": meta.get("TOOL_VERSION", "0.1.0"),
        "generated_utc": meta.get("TS_END_UTC", ""),
        "is_baseline_grade": is_baseline_grade,
        "baseline_grade_reasons": baseline_reasons,
        "host": {
            "hostname": meta.get("HOSTNAME", ""),
            "os": meta.get("OS", ""),
            "os_pretty": meta.get("OS_PRETTY", ""),
            "arch": meta.get("ARCH", ""),
            "kernel": meta.get("KERNEL", ""),
            "is_rpi": is_rpi,
            "rpi_model": meta.get("RPI_MODEL", ""),
            "cpu_brand": meta.get("CPU_BRAND", ""),
            "ncpu": to_int(meta.get("NCPU")),
            "ram_bytes": to_int(meta.get("RAM_BYTES")),
        },
        "cpu_features": features,
        "run": {
            "timestamp_start_utc": meta.get("TS_START_UTC", ""),
            "timestamp_end_utc": meta.get("TS_END_UTC", ""),
            "duration_s": to_int(meta.get("DURATION_S")),
            "governor_requested": meta.get("GOVERNOR_REQUESTED", ""),
            "governor_before": meta.get("GOVERNOR_BEFORE", ""),
            "governor_after": meta.get("GOVERNOR_AFTER", ""),
            "bench_core": to_int(meta.get("BENCH_CORE")),
            "pinned": pinned,
            "taskset_cmd": meta.get("TASKSET_CMD", ""),
            # Per-op sizing. In auto-calibration mode warmup_iters/timed_iters are
            # chosen per operation (see each entry under kem/sig "operations");
            # the run-level target/min/max below describe how they were derived.
            "calibration_mode": meta.get("CALIB_MODE", "auto"),
            "target_time_ms": to_int(meta.get("TARGET_TIME_MS")),
            "min_samples": to_int(meta.get("MIN_SAMPLES")),
            "max_iters": to_int(meta.get("MAX_ITERS")),
            "warmup_iters": to_int(meta.get("WARMUP")),
            "timed_iters": to_int(meta.get("ITERS")),
            "repetitions": to_int(meta.get("REPS")),
            "cycles_mode": meta.get("CYCLES_MODE", ""),
            "cycles_available": meta.get("CYCLES_AVAILABLE") == "1",
            "cycles_reason": meta.get("CYCLES_REASON", ""),
        },
        "toolchain": {
            "cc_version": lock.get("CC_VERSION", ""),
            "bench_cflags": lock.get("BENCH_CFLAGS", ""),
            "cflags_target": cflags_target,
            "liboqs_ref": lock.get("LIBOQS_REF", ""),
            "liboqs_commit": lock.get("LIBOQS_COMMIT", ""),
            "liboqs_opt_defines": lock.get("LIBOQS_OPT_DEFINES", ""),
            "openssl": lock.get("OPENSSL_COMMIT", ""),
            "oqsprovider_ref": lock.get("OQSPROVIDER_REF", ""),
            "oqsprovider_commit": lock.get("OQSPROVIDER_COMMIT", ""),
            "rust": rust_toolchain,
            "rust_tls": rust_tls_toolchain,
        },
        "thermal_trace": thermal,
        "warnings": warnings,
        "kem": kem_rows,
        "sig": sig_rows,
        "tls": tls,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(args.out)


if __name__ == "__main__":
    main()
