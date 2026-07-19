# Dashboard

Static, no-backend dashboard (Chart.js) for the merged benchmark dataset.

## Viewing it — must be served over HTTP

The page loads `data/merged.json` with `fetch()`. Browsers block that fetch for
pages opened as plain files (`file://` origins have no cross-origin rights), so
**opening `index.html` directly shows empty charts**. Serve the directory over
HTTP instead:

```sh
cd dashboard
python3 -m http.server 8000
# open http://localhost:8000   (or http://<pi-ip>:8000 from another machine)
```

Any static host works the same way (GitHub Pages included — deploy this
directory as-is).

## What the merged dataset contains

`data/merged.json` is produced by `analyze/merge.py` (schema `2.0.0`). Run with
no arguments it merges exactly the files pinned in
`analyze/published_runs.txt` — currently the three baseline-grade RPi5 runs
plus the published Mac (Apple M3) cross-platform comparison run (not
baseline-grade; hidden by the dashboard's default filter). Ad-hoc dev runs in
`results/` never enter the published dataset unless added to that manifest.

Contents:

- `runs[]` — one record per source file: host facts, toolchain provenance
  (liboqs/OpenSSL/oqs-provider versions + commits, build flags), thermal
  summary, and the `is_baseline_grade` verdict with reasons.
- `kem[]` / `sig[]` — flat per-(run, algorithm, operation) rows: median/MAD/
  IQR/min/stddev/ops-per-sec, sizes, NIST level, `classical` flag,
  `implementation` (which library produced the measurement — `liboqs`,
  `openssl`; later stages add `rustcrypto`), and the per-algorithm
  `total_sum_of_medians_ns` aggregate (derived: sum of per-op medians).
- `tls[]` — flat per-(run, matrix-cell) rows: handshake latency median,
  handshakes/sec, bytes on wire, ClientHello size + fragmentation flag, plus
  `phase` (`baseline` / `phase0` / `phase2` migration phases), `sig_alg`,
  `implementation` (`oqs-provider` today; later stages add `openssl-native`
  and `rustls-awslc`), and `primitive_sum_of_medians_ns` — the sum of the
  primitive operations one handshake performs (with
  `primitive_sum_complete=false` when a component, e.g. P-256 ECDH, is not
  measured as a primitive). Full per-component breakdowns live in the source
  results files under `tls.matrix[].handshake_primitive_sum`.

Schema-1.0.0 result files are merged compatibly (`backend` →
`implementation`, phase inferred, totals derived) without rewriting them.

The charts currently group by security level / operation / run; charting of
the new `implementation` and `phase` dimensions is a planned, separate change —
the fields are in the data now so old and new merges stay uniform.
