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

SCHEMA_VERSION = "1.0.0"


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--meta", required=True)
    ap.add_argument("--lock", default="")
    ap.add_argument("--features", default="")
    ap.add_argument("--kemsig", default="")
    ap.add_argument("--tls", default="")
    ap.add_argument("--thermal", default="")
    ap.add_argument("--config", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    meta = parse_envfile(args.meta)
    lock = parse_envfile(args.lock)
    features = load_json(args.features) or {}
    kemsig = load_jsonl(args.kemsig)
    tls = load_json(args.tls)
    thermal = parse_thermal(args.thermal)

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
        },
        "thermal_trace": thermal,
        "warnings": warnings,
        "kem": [r for r in kemsig if r.get("kind") == "kem"],
        "sig": [r for r in kemsig if r.get("kind") == "sig"],
        "tls": tls,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(args.out)


if __name__ == "__main__":
    main()
