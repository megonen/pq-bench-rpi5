#!/usr/bin/env python3
"""plot.py — export publication-ready PNGs from a merged dataset.

  python3 analyze/plot.py dashboard/data/merged.json -o analyze/png

matplotlib is an OPTIONAL dependency. If it is not installed this prints a clear
hint and exits 0 (the HTML dashboard remains the primary, dependency-free view).

By default it plots only baseline-grade (RPi5) runs so paper figures are never
polluted with macOS smoke data; pass --include-smoke to override. The classical
Logos baseline (X25519 / Ed25519) is drawn as a reference line on every chart.
"""
from __future__ import annotations
import argparse
import json
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib not installed — skipping PNG export.\n"
          "  enable it in a project venv (keeps your system python clean):\n"
          "    python3 -m venv analyze/.venv\n"
          "    analyze/.venv/bin/pip install -r analyze/requirements.txt\n"
          "    analyze/.venv/bin/python analyze/plot.py dashboard/data/merged.json\n"
          "  (the HTML dashboard works without it)", file=sys.stderr)
    sys.exit(0)


def median_ms(ns):
    return (ns or 0) / 1e6


def pick_runs(merged, include_smoke):
    ids = set()
    for r in merged.get("runs", []):
        if include_smoke or r.get("is_baseline_grade"):
            ids.add(r["run_id"])
    return ids


def grouped_bar_by_level(rows, op, title, outpath):
    """Grouped bars of median latency per algorithm, grouped by NIST level."""
    data = [r for r in rows if r["operation"] == op]
    if not data:
        return
    # one bar per algorithm; baseline highlighted
    data.sort(key=lambda r: (r.get("nist_level") or 0, r["median_ns"]))
    labels = [r["alg"] for r in data]
    vals = [median_ms(r["median_ns"]) for r in data]
    colors = ["#888" if r.get("classical") else "#3b6" for r in data]

    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.55), 4))
    ax.bar(range(len(labels)), vals, color=colors)
    # baseline reference line
    base = next((r for r in data if r.get("classical")), None)
    if base:
        ax.axhline(median_ms(base["median_ns"]), color="#c33", ls="--", lw=1,
                   label=f"classical baseline ({base['alg']})")
        ax.legend(fontsize=8)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("median latency (ms)")
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print("wrote", outpath)


def size_speed_scatter(rows, op, size_key, title, outpath):
    data = [r for r in rows if r["operation"] == op and r.get("sizes")]
    pts = []
    for r in data:
        sz = (r["sizes"] or {}).get(size_key)
        if sz:
            pts.append((sz, median_ms(r["median_ns"]), r["alg"], r.get("classical")))
    if not pts:
        return
    fig, ax = plt.subplots(figsize=(7, 5))
    for sz, lat, alg, classical in pts:
        ax.scatter(sz, lat, c="#c33" if classical else "#3b6",
                   s=60, edgecolors="k", linewidths=0.4, zorder=3)
        ax.annotate(alg, (sz, lat), fontsize=7, xytext=(4, 3),
                    textcoords="offset points")
    ax.set_xlabel(f"{size_key} size (bytes)")
    ax.set_ylabel("median latency (ms)")
    ax.set_title(title)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print("wrote", outpath)


def tls_bar(tls_rows, outpath):
    if not tls_rows:
        return
    tls_rows = sorted(tls_rows, key=lambda r: -(r.get("handshakes_per_sec") or 0))
    labels = [r["label"] for r in tls_rows]
    vals = [r.get("handshakes_per_sec") or 0 for r in tls_rows]
    colors = ["#c33" if r.get("is_baseline_pair") else "#36c" for r in tls_rows]
    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.5), 4.5))
    ax.barh(range(len(labels)), vals, color=colors)
    base = next((r for r in tls_rows if r.get("is_baseline_pair")), None)
    if base:
        ax.axvline(base.get("handshakes_per_sec") or 0, color="#c33", ls="--", lw=1,
                   label=f"classical baseline ({base['label']})")
        ax.legend(fontsize=8)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("handshakes / sec")
    ax.set_title("TLS 1.3 handshake throughput (higher is better)")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print("wrote", outpath)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("merged")
    ap.add_argument("-o", "--outdir", default="analyze/png")
    ap.add_argument("--include-smoke", action="store_true")
    args = ap.parse_args()

    with open(args.merged) as f:
        merged = json.load(f)
    ids = pick_runs(merged, args.include_smoke)
    if not ids:
        print("no baseline-grade runs to plot (use --include-smoke for macOS/dev data)",
              file=sys.stderr)
        return

    def keep(rows):
        return [r for r in rows if r["run_id"] in ids]

    kem, sig, tls = keep(merged["kem"]), keep(merged["sig"]), keep(merged["tls"])
    os.makedirs(args.outdir, exist_ok=True)
    O = args.outdir

    grouped_bar_by_level(kem, "keygen", "KEM keygen latency by algorithm", f"{O}/kem_keygen.png")
    grouped_bar_by_level(kem, "encaps", "KEM encapsulation latency", f"{O}/kem_encaps.png")
    grouped_bar_by_level(kem, "decaps", "KEM decapsulation latency", f"{O}/kem_decaps.png")
    grouped_bar_by_level(sig, "sign", "Signature signing latency", f"{O}/sig_sign.png")
    grouped_bar_by_level(sig, "verify", "Signature verification latency", f"{O}/sig_verify.png")
    size_speed_scatter(kem, "encaps", "public_key",
                       "KEM: public-key size vs encaps latency", f"{O}/kem_size_speed.png")
    size_speed_scatter(sig, "sign", "signature",
                       "Signature: signature size vs sign latency", f"{O}/sig_size_speed.png")
    tls_bar(tls, f"{O}/tls_throughput.png")
    print(f"PNGs in {O}/ ({'incl. smoke' if args.include_smoke else 'baseline-grade only'})")


if __name__ == "__main__":
    main()
