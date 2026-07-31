#!/usr/bin/env python3
"""merge.py — merge many results/<host>-<ts>.json files into one dataset the
dashboard (and PNG export) consume.

  python3 analyze/merge.py                    # merge the PUBLISHED set (see below)
  python3 analyze/merge.py results/*.json ... # merge an explicit ad-hoc set

With no inputs, the file list comes from analyze/published_runs.txt — the
explicit, reviewed manifest of which results files feed the published dashboard
dataset. That keeps ad-hoc dev runs sitting in results/ from silently leaking
into dashboard/data/merged.json: getting a run published is an edit to the
manifest, not an accident of globbing.

The merged file keeps every run as a separate record (so multiple machines /
repetitions can be compared) plus a flat index for quick charting. It never
collapses RPi5 baseline-grade runs together with non-baseline (e.g. macOS smoke)
runs — each record carries its own `is_baseline_grade` flag and host, and the
dashboard filters on it by default.

Schema-v1 inputs (pre-`implementation`/`phase` result files) are read
compatibly: `backend` maps to `implementation`, TLS rows get their phase
inferred (classical sig + classical group = baseline; PQ signature = phase2;
PQ/hybrid group + classical sig = phase0), and TLS implementation defaults to
"oqs-provider" (the only TLS stack that existed before v2). The source files
are never rewritten.
"""
from __future__ import annotations
import argparse
import glob
import json
import os
import sys

MERGED_SCHEMA = "2.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(HERE, "published_runs.txt")

PQ_KEM_TOKENS = ("mlkem", "kyber", "frodo", "hqc", "bike", "ntru", "mceliece")
CLASSICAL_SIG_PREFIXES = ("ed25519", "ed448", "ecdsa", "rsa")


def infer_phase(group: str, sig_alg: str) -> str:
    """v1-compat phase inference; keep in sync with bench/lib/assemble.py."""
    g, s = (group or "").lower(), (sig_alg or "").lower()
    pq_kem = any(t in g for t in PQ_KEM_TOKENS)
    if s.startswith(CLASSICAL_SIG_PREFIXES):
        return "phase0" if pq_kem else "baseline"
    return "phase2"


def row_total(row):
    """Per-alg total (sum of per-op medians). Prefer the value assemble.py
    stamped; for v1 files (which are never rewritten) derive it here so old
    and new runs chart uniformly. Derived, not measured."""
    t = (row.get("total") or {}).get("sum_of_medians_ns")
    if t is not None:
        return t
    # keep in sync with assemble.py TOTAL_OPS: auxiliary ops (e.g.
    # verify_cached_key) are not part of the one-full-cycle total
    total_ops = ("keygen", "encaps", "decaps", "derive", "sign", "verify")
    medians = [(st or {}).get("median")
               for op, st in (row.get("operations") or {}).items()
               if op in total_ops]
    if medians and all(m is not None for m in medians):
        return round(sum(medians), 2)
    return None


def manifest_paths():
    if not os.path.exists(MANIFEST):
        sys.exit(f"no inputs given and manifest not found: {MANIFEST}")
    paths = []
    with open(MANIFEST) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = line if os.path.isabs(line) else os.path.join(ROOT, "results", line)
            if os.path.isfile(p):
                paths.append(p)
            else:
                print(f"[merge] manifest entry missing on disk (skipped): {line}",
                      file=sys.stderr)
    return paths


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
    """Produce flat per-(run, algorithm, operation) rows for easy charting.
    Deliberately-disabled rows are NOT dropped: they flow into the *_absent
    arrays with their reasons — absences (e.g. SLH-DSA in TLS) are findings
    the dashboard must render, not gaps to silently filter."""
    kem_rows, sig_rows, tls_rows = [], [], []
    kem_absent, sig_absent, tls_absent = [], [], []
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
                kem_absent.append({**meta, "alg": k.get("alg"),
                    "implementation": k.get("implementation") or k.get("backend"),
                    "reason": k.get("reason", "")})
                continue
            for op, st in (k.get("operations") or {}).items():
                kem_rows.append({**meta,
                    "alg": k["alg"],
                    # v1 files say `backend`; same meaning, injected as default
                    "implementation": k.get("implementation") or k.get("backend"),
                    "classical": bool(k.get("classical")),
                    "nist_level": k.get("claimed_nist_level"),
                    "operation": op,
                    "median_ns": st.get("median"), "mad_ns": st.get("mad"),
                    "iqr_ns": st.get("iqr"), "min_ns": st.get("min"),
                    "stddev_ns": st.get("stddev"), "ops_per_sec": st.get("ops_per_sec"),
                    "total_sum_of_medians_ns": row_total(k),
                    "acceleration": k.get("acceleration"),
                    "sizes": k.get("sizes")})
        for s in run.get("sig", []):
            if not s.get("enabled"):
                sig_absent.append({**meta, "alg": s.get("alg"),
                    "implementation": s.get("implementation") or s.get("backend"),
                    "reason": s.get("reason", "")})
                continue
            for op, st in (s.get("operations") or {}).items():
                sig_rows.append({**meta,
                    "alg": s["alg"],
                    "implementation": s.get("implementation") or s.get("backend"),
                    "classical": bool(s.get("classical")),
                    "nist_level": s.get("claimed_nist_level"),
                    "operation": op,
                    "median_ns": st.get("median"), "mad_ns": st.get("mad"),
                    "iqr_ns": st.get("iqr"), "min_ns": st.get("min"),
                    "stddev_ns": st.get("stddev"), "ops_per_sec": st.get("ops_per_sec"),
                    "total_sum_of_medians_ns": row_total(s),
                    "acceleration": s.get("acceleration"),
                    "sizes": s.get("sizes")})
        tls = run.get("tls") or {}
        for cell in (tls.get("matrix") or []):
            if not cell.get("enabled"):
                lab = cell.get("label") or ""
                tls_absent.append({**meta, "label": lab,
                    "group": cell.get("group"),
                    "sig_alg": cell.get("sig_alg") or
                        (lab.split("+", 1)[1] if "+" in lab else ""),
                    "phase": cell.get("phase") or "",
                    "implementation": cell.get("implementation") or "oqs-provider",
                    "unstable_features": cell.get("unstable_features", False),
                    "reason": cell.get("reason", "")})
                continue
            label = cell.get("label") or ""
            sig_alg = cell.get("sig_alg") or \
                (label.split("+", 1)[1] if "+" in label else "")
            hps = cell.get("handshake_primitive_sum") or {}
            tls_rows.append({**meta,
                "label": label, "group": cell.get("group"),
                "sig_alg": sig_alg,
                # v1 files predate these fields; defaults describe what those
                # runs actually were (oqs-provider stack, phase by inference)
                "implementation": cell.get("implementation") or "oqs-provider",
                "unstable_features": cell.get("unstable_features", False),
                "phase": cell.get("phase") or infer_phase(cell.get("group"), sig_alg),
                "is_baseline_pair": label == (tls.get("baseline") or {}).get("label"),
                "handshakes_per_sec": cell.get("handshakes_per_sec"),
                "median_ns": (cell.get("handshake_latency_ns") or {}).get("median"),
                "primitive_sum_of_medians_ns": hps.get("sum_of_medians_ns"),
                "primitive_sum_complete": hps.get("complete"),
                "bytes_total": (cell.get("bytes_on_wire") or {}).get("total"),
                "client_hello_bytes": cell.get("client_hello_bytes"),
                "client_hello_fragmented": cell.get("client_hello_fragmented")})
    return (kem_rows, sig_rows, tls_rows,
            kem_absent, sig_absent, tls_absent)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="*",
                    help="results JSON files or globs; empty = the published "
                         "set from analyze/published_runs.txt")
    ap.add_argument("-o", "--out", default="dashboard/data/merged.json")
    args = ap.parse_args()

    if args.inputs:
        paths = []
        for pat in args.inputs:
            paths.extend(sorted(glob.glob(pat)) if any(c in pat for c in "*?[") else [pat])
        paths = [p for p in paths if os.path.isfile(p)]
    else:
        paths = manifest_paths()
        print(f"[merge] no inputs given -> published set from {MANIFEST} "
              f"({len(paths)} files)", file=sys.stderr)
    if not paths:
        sys.exit("no input files matched")

    runs = load_runs(paths)
    (kem_rows, sig_rows, tls_rows,
     kem_absent, sig_absent, tls_absent) = flatten(runs)

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
        "kem_absent": kem_absent,
        "sig_absent": sig_absent,
        "tls_absent": tls_absent,
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
