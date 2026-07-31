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
`analyze/published_runs.txt` — the published Logos snapshot set cited by the
companion document's provenance section: the consolidated baseline-grade RPi5
run, the consolidated Mac (Apple M3) cross-platform run (not baseline-grade;
hidden by the dashboard's default filter), and the community RPi5 run
(`thomas-pi-*`; merged once its file lands in `results/`). Ad-hoc dev runs in
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

## Views

- **TLS migration phases** — baseline → phase0 → phase2 for a chosen group
  family and stack, latency and bytes-on-wire side by side, **Pi and Mac in
  the same chart** (Mac bars translucent), with ×multipliers vs each
  platform's own classical baseline. The ◆ marker on latency bars is the
  handshake's **sum of primitive-operation medians** (derived, not measured —
  labelled as such in the panel); the gap to the bar top is protocol overhead.
- **Full handshake matrix** — every cell of the selected run, colored by
  phase, banded by stack; ᵁ marks rows riding unstable cargo features. Plus
  the ClientHello chart with the ~1400 B MSS line (orange border = fragments).
- **Cross-implementation primitives** — same algorithm measured by
  independent implementations (Pi solid / Mac translucent), log axis by
  default. Acceleration context appears three ways: hatched bars = portable
  code path (secondary cue), tooltips carry the full per-row acceleration
  record, and the **always-visible acceleration table** underneath
  (arithmetic path, symmetric path, per-platform hardware-instruction status)
  is authoritative — so asm-vs-portable is never mistaken for implementation
  quality.
- **Primitives by security level** — the original charts, preserved, with an
  implementation filter (classical anchors come from the matching family:
  openssl for liboqs, in-family for the Rust groups) and log axes by default
  so five orders of magnitude (16 µs ML-KEM keygen … 0.5 s SLH-DSA-128s sign)
  are all visible; linear toggle for same-magnitude comparison.
- **Deliberate absences** — disabled rows rendered as cards with their
  verbatim reasons (SLH-DSA-in-TLS first: unavailable in both production
  stacks, oqs-provider only). Never bars, never zeros, never filtered away.

Both published runs are **shown by default**: the Pi card is baseline-grade,
the Mac card is labelled "cross-platform reference — not baseline-grade" with
its reasons expandable — a labelling distinction, not a visibility one.
