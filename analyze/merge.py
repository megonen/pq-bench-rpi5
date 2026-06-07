#!/usr/bin/env python3
"""merge.py — merge many results/<host>-<ts>.json files into one dataset the
dashboard (and PNG export) consume.

  python3 analyze/merge.py results/*.json -o dashboard/data/merged.json

The merged file keeps every run as a separate record (so multiple machines /
repetitions can be compared) plus a flat index for quick charting. It never
collapses RPi5 baseline-grade runs together with non-baseline (e.g. macOS smoke)
runs — each record carries its own `is_baseline_grade` flag and host, and the
dashboard filters on it by default.
"""
from __future__ import annotations
import argparse
import glob
import json
import os
import sys

MERGED_SCHEMA = "1.0.0"


def load_runs(paths):
    runs = []
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
            d["_source_file"] = os.path.basename(p)
            runs.append(d)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[merge] skipping {p}: {e}", file=sys.stderr)
    return runs


def run_id(run):
    h = run.get("host", {})
    return f"{h.get('hostname','?')}/{h.get('cpu_brand','?')}@{run.get('generated_utc','?')}"


def flatten(runs):
    """Produce flat per-(run, algorithm, operation) rows for easy charting."""
    kem_rows, sig_rows, tls_rows = [], [], []
    for run in runs:
        rid = run_id(run)
        host = run.get("host", {})
        meta = {
            "run_id": rid,
            "hostname": host.get("hostname"),
            "cpu_brand": host.get("cpu_brand"),
            "is_rpi": host.get("is_rpi"),
            "is_baseline_grade": run.get("is_baseline_grade"),
            "source_file": run.get("_source_file"),
        }
        for k in run.get("kem", []):
            if not k.get("enabled"):
                continue
            for op, st in (k.get("operations") or {}).items():
                kem_rows.append({**meta,
                    "alg": k["alg"], "backend": k.get("backend"),
                    "classical": bool(k.get("classical")),
                    "nist_level": k.get("claimed_nist_level"),
                    "operation": op,
                    "median_ns": st.get("median"), "mad_ns": st.get("mad"),
                    "iqr_ns": st.get("iqr"), "min_ns": st.get("min"),
                    "stddev_ns": st.get("stddev"), "ops_per_sec": st.get("ops_per_sec"),
                    "sizes": k.get("sizes")})
        for s in run.get("sig", []):
            if not s.get("enabled"):
                continue
            for op, st in (s.get("operations") or {}).items():
                sig_rows.append({**meta,
                    "alg": s["alg"], "backend": s.get("backend"),
                    "classical": bool(s.get("classical")),
                    "nist_level": s.get("claimed_nist_level"),
                    "operation": op,
                    "median_ns": st.get("median"), "mad_ns": st.get("mad"),
                    "iqr_ns": st.get("iqr"), "min_ns": st.get("min"),
                    "stddev_ns": st.get("stddev"), "ops_per_sec": st.get("ops_per_sec"),
                    "sizes": s.get("sizes")})
        tls = run.get("tls") or {}
        for cell in (tls.get("matrix") or []):
            if not cell.get("enabled"):
                continue
            tls_rows.append({**meta,
                "label": cell.get("label"), "group": cell.get("group"),
                "is_baseline_pair": cell.get("label") == (tls.get("baseline") or {}).get("label"),
                "handshakes_per_sec": cell.get("handshakes_per_sec"),
                "median_ns": (cell.get("handshake_latency_ns") or {}).get("median"),
                "bytes_total": (cell.get("bytes_on_wire") or {}).get("total"),
                "client_hello_bytes": cell.get("client_hello_bytes"),
                "client_hello_fragmented": cell.get("client_hello_fragmented")})
    return kem_rows, sig_rows, tls_rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="results JSON files or globs")
    ap.add_argument("-o", "--out", default="dashboard/data/merged.json")
    args = ap.parse_args()

    paths = []
    for pat in args.inputs:
        paths.extend(sorted(glob.glob(pat)) if any(c in pat for c in "*?[") else [pat])
    paths = [p for p in paths if os.path.isfile(p)]
    if not paths:
        sys.exit("no input files matched")

    runs = load_runs(paths)
    kem_rows, sig_rows, tls_rows = flatten(runs)

    merged = {
        "merged_schema": MERGED_SCHEMA,
        "n_runs": len(runs),
        "runs": [{
            "run_id": run_id(r),
            "host": r.get("host"),
            "is_baseline_grade": r.get("is_baseline_grade"),
            "baseline_grade_reasons": r.get("baseline_grade_reasons", []),
            "toolchain": r.get("toolchain"),
            "cpu_features": r.get("cpu_features"),
            "run": r.get("run"),
            "thermal_summary": {
                "temp_c": (r.get("thermal_trace") or {}).get("temp_c"),
                "throttling_detected": (r.get("thermal_trace") or {}).get("throttling_detected"),
            },
            "generated_utc": r.get("generated_utc"),
            "source_file": r.get("_source_file"),
        } for r in runs],
        "kem": kem_rows,
        "sig": sig_rows,
        "tls": tls_rows,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(merged, f, indent=2)
    n_base = sum(1 for r in runs if r.get("is_baseline_grade"))
    print(f"merged {len(runs)} run(s) -> {args.out}  "
          f"({n_base} baseline-grade, {len(runs)-n_base} smoke/other)")
    print(f"  kem rows: {len(kem_rows)}  sig rows: {len(sig_rows)}  tls rows: {len(tls_rows)}")


if __name__ == "__main__":
    main()
