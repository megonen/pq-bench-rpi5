#!/usr/bin/env bash
# =============================================================================
# run.sh — measurement wrapper + orchestrator.
#
# Does the things that make a number credible:
#   * sets the CPU governor to `performance` (Linux; warns elsewhere)
#   * pins the benchmark to a single isolated core via taskset (core 3 on RPi5;
#     core 3 stays clear of CPU0 where the kernel steers IRQs/RPS)
#   * logs ARM clock + SoC temperature throughout, embeds the trace in results,
#     and warns on thermal throttling
#   * runs every candidate from config.yaml, then assembles one results JSON
#     stamped with full host + toolchain provenance.
#
# Usage:
#   ./run.sh                 # full run using config.yaml knobs
#   ./run.sh --smoke         # tiny iteration counts: pipeline smoke test
#   ./run.sh --kemsig-only   # skip the TLS layer
#   ./run.sh --tls-only      # only the TLS layer
#   ./run.sh --iters N --warmup N --reps N   # override measurement knobs
#
# Prefer `make run` / `make smoke`: on Linux they cache sudo credentials once
# so the CPU-governor step (the ONLY privileged operation) can escalate via
# `sudo -n`, while the measurement itself runs as your user. NOSUDO=1 (or
# declining sudo) still completes the run with the governor demerit recorded.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_VERSION="0.2.0"
# shellcheck source=setup/lib_platform.sh
source "$ROOT/setup/lib_platform.sh"
# shellcheck source=setup/versions.env
source "$ROOT/setup/versions.env"
LOCK="$ROOT/setup/versions.lock"
[ -f "$LOCK" ] && source "$LOCK" || pqb_warn "no versions.lock — run ./setup/setup.sh first"

pqb_detect_platform

# `set -e` deaths must never be silent: report the failing command and line.
# (A generic-x86 run previously exited 1 with no output at all when a
# platform probe failed mid-run — this trap makes that class of failure
# diagnosable wherever it happens next.)
set -E  # errtrace: without it the ERR trap does not fire inside functions
trap 'pqb_err "run.sh aborted at line $LINENO while running: $BASH_COMMAND"' ERR

# Rust flag parity with the C side (recorded in the Rust provenance blocks):
# the same host-tuning the C builds got, expressed as target-cpu.
case "${CFLAGS_TARGET:-}" in
  cortex-a76)             export RUSTFLAGS="-C target-cpu=cortex-a76" ;;
  apple-m*|apple-silicon) export RUSTFLAGS="-C target-cpu=native" ;;
esac

# ---- args ------------------------------------------------------------------
SMOKE=0; DO_KEMSIG=1; DO_TLS=1
OVR_ITERS=""; OVR_WARMUP=""; OVR_REPS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SMOKE=1 ;;
    --kemsig-only) DO_TLS=0 ;;
    --tls-only) DO_KEMSIG=0 ;;
    --no-tls) DO_TLS=0 ;;
    --iters) OVR_ITERS="$2"; shift ;;
    --warmup) OVR_WARMUP="$2"; shift ;;
    --reps) OVR_REPS="$2"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) pqb_err "unknown arg: $1"; exit 2 ;;
  esac
  shift
done

# ---- measurement knobs (config.yaml, overridable) --------------------------
# Sets TARGET_TIME_MS MIN_SAMPLES MAX_ITERS REPS CYCLES_MODE (auto-calibration,
# the default path) plus WARMUP ITERS (the fixed-count fallback).
eval "$(python3 "$ROOT/bench/lib/list_algs.py" measurement "$ROOT/config.yaml")"

# Mode: auto-calibrate per op (default) unless --iters forces a fixed count.
CALIB_MODE="auto"
if [ -n "$OVR_ITERS" ]; then CALIB_MODE="fixed"; ITERS="$OVR_ITERS"; fi
[ -n "$OVR_WARMUP" ] && WARMUP="$OVR_WARMUP"
[ -n "$OVR_REPS" ]   && REPS="$OVR_REPS"
if [ "$SMOKE" = 1 ]; then
  # Keep auto-calibration (so each op still reaches target) but a single rep, so
  # the sweep stays short. This is a pipeline test, NOT measurement data.
  REPS=1
  pqb_warn "SMOKE MODE: reps=1 — pipeline test only, NOT measurement data"
fi

# Assemble the per-op sizing args passed to every bench_pq invocation.
if [ "$CALIB_MODE" = "fixed" ]; then
  BENCH_SIZE_ARGS=(--warmup "$WARMUP" --iters "$ITERS" --reps "$REPS")
  pqb_log "sizing: FIXED-count warmup=$WARMUP iters=$ITERS reps=$REPS"
else
  BENCH_SIZE_ARGS=(--target-time-ms "$TARGET_TIME_MS" --min-samples "$MIN_SAMPLES" \
                   --max-iters "$MAX_ITERS" --reps "$REPS")
  pqb_log "sizing: AUTO-calibrate target=${TARGET_TIME_MS}ms min_samples=$MIN_SAMPLES max_iters=$MAX_ITERS reps=$REPS"
fi
BENCH_CORE="${BENCH_CORE:-3}"
export PQB_BENCH_CORE="$BENCH_CORE"

# ---- work directory --------------------------------------------------------
HOST="$(pqb_resolve_hostname)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$ROOT/results/.work-$HOST-$TS"
mkdir -p "$WORK" "$ROOT/results"
KEMSIG_OUT="$WORK/kemsig.jsonl"; : > "$KEMSIG_OUT"
TLS_OUT="$WORK/tls.json"
RUST_TLS_PROV=""   # set when the TLS layer runs (rustls provenance path)
THERMAL="$WORK/thermal.csv"; : > "$THERMAL"
META="$WORK/meta.env"
FEATURES="$WORK/cpu_features.json"
WARN_ACC=""

add_warn() { WARN_ACC="${WARN_ACC:+$WARN_ACC||}$1"; pqb_warn "$1"; }

# ---- governor --------------------------------------------------------------
GOV_BEFORE="$(pqb_get_governor)"
GOV_AFTER="$(pqb_set_governor_performance || true)"
GOV_REQUESTED="performance"
if [ "$GOV_AFTER" != "performance" ]; then
  add_warn "governor is '$GOV_AFTER', not 'performance' (on Linux run via 'make run' so the governor step can escalate; no governor control on macOS)"
fi

# ---- core pinning ----------------------------------------------------------
TASKSET="$(pqb_taskset_prefix "$BENCH_CORE")"
if [ -n "$TASKSET" ]; then
  PINNED=1; pqb_log "pinning to core $BENCH_CORE via: $TASKSET"
else
  PINNED=0; add_warn "core pinning unavailable (no taskset/numactl) — results will be noisier"
fi

# ---- thermal sampler (background) ------------------------------------------
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
pqb_log "starting thermal/clock sampler (every ${SAMPLE_INTERVAL}s) -> $THERMAL"
( while :; do pqb_sample_thermal >> "$THERMAL" 2>/dev/null; sleep "$SAMPLE_INTERVAL"; done ) &
SAMPLER_PID=$!
disown "$SAMPLER_PID" 2>/dev/null || true   # suppress job-control "Terminated" noise on kill
# shellcheck disable=SC2064
trap "kill $SAMPLER_PID 2>/dev/null || true" EXIT
pqb_sample_thermal >> "$THERMAL" 2>/dev/null || true   # one immediate sample
# (|| true: on machines with no thermal telemetry the sampler records empty
# fields; a sampler hiccup must never abort a measurement run — temperature
# is then honestly reported unavailable, as on macOS)

# ---- CPU features ----------------------------------------------------------
pqb_cpu_features_json > "$FEATURES"
pqb_log "cpu features: $(cat "$FEATURES")"
# Report whether Keccak/SHA3 *instruction* acceleration is available + compiled.
SHA3_HW="$(python3 -c "import json;print(json.load(open('$FEATURES'))['sha3'])" 2>/dev/null || echo unknown)"
case "${LIBOQS_OPT_DEFINES:-}" in
  *"OQS_USE_ARM_SHA3_INSTRUCTIONS 1"*) SHA3_COMPILED=1 ;;
  *) SHA3_COMPILED=0 ;;
esac
pqb_log "Keccak/SHA3: hw_instructions=$SHA3_HW liboqs_compiled_sha3=$SHA3_COMPILED (A76 has no SHA3 ext; Keccak runs on NEON there)"

TS_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"

# ---- build harness if needed -----------------------------------------------
OSSL_PREFIX_FOR_BUILD="${OPENSSL_PREFIX:-$(brew --prefix openssl@3.5 2>/dev/null || echo /usr)}"
if [ ! -x "$ROOT/bench/kem_sig/bench_pq" ] || [ "$ROOT/bench/kem_sig/bench_pq.c" -nt "$ROOT/bench/kem_sig/bench_pq" ]; then
  pqb_log "building bench_pq harness"
  make -C "$ROOT/bench/kem_sig" \
    LIBOQS_PREFIX="${PREFIX:-$ROOT/vendor/install}" \
    OPENSSL_PREFIX="$OSSL_PREFIX_FOR_BUILD" \
    BENCH_CFLAGS="${BENCH_CFLAGS:--O3}" >/dev/null
fi

# ---- KEM/sig sweep ---------------------------------------------------------
CYCLES_AVAILABLE=0; CYCLES_REASON="not probed"
if [ "$DO_KEMSIG" = 1 ]; then
  if [ "$CALIB_MODE" = "fixed" ]; then
    pqb_log "running KEM/sig sweep (fixed: warmup=$WARMUP iters=$ITERS reps=$REPS)"
  else
    pqb_log "running KEM/sig sweep (auto-calibrate: target=${TARGET_TIME_MS}ms min_samples=$MIN_SAMPLES max_iters=$MAX_ITERS reps=$REPS)"
  fi
  while IFS=$'\t' read -r kind alg classical; do
    [ -z "$alg" ] && continue
    pqb_log "  $kind $alg"
    ERRF="$WORK/err.$kind.$alg.txt"
    # shellcheck disable=SC2086
    if $TASKSET "$ROOT/bench/kem_sig/bench_pq" --kind "$kind" --alg "$alg" \
        "${BENCH_SIZE_ARGS[@]}" >> "$KEMSIG_OUT" 2>"$ERRF"; then
      :
    else
      add_warn "harness failed for $kind $alg (see $ERRF)"
    fi
    # capture PMU availability from the harness's stderr (first occurrence)
    if grep -q 'cycles_available=1' "$ERRF" 2>/dev/null; then
      CYCLES_AVAILABLE=1; CYCLES_REASON="$(sed -n 's/.*cycles_available=1 (\(.*\))/\1/p' "$ERRF" | head -1)"
    elif [ "$CYCLES_AVAILABLE" = 0 ] && grep -q 'cycles_available=0' "$ERRF" 2>/dev/null; then
      CYCLES_REASON="$(sed -n 's/.*cycles_available=0 (\(.*\))/\1/p' "$ERRF" | head -1)"
    fi
  done < <(python3 "$ROOT/bench/lib/list_algs.py" kemsig "$ROOT/config.yaml")
fi

# ---- Rust (RustCrypto) KEM/sig sweep ---------------------------------------
# Second, independent measurement group: pure-Rust implementations, same
# methodology (pqb-rust replicates bench_pq.c's calibration/stats), same
# kemsig.jsonl, rows tagged implementation:"rustcrypto". If the Rust toolchain
# is absent the group is SKIPPED and the reason recorded — never faked.
RUST_PROV="$WORK/rust_provenance.json"
if [ "$DO_KEMSIG" = 1 ]; then
  if command -v cargo >/dev/null 2>&1; then
    pqb_log "building Rust harness (cargo build --release --locked)"
    if (cd "$ROOT/bench/rust" && cargo build --release --locked) >"$WORK/rust_build.log" 2>&1; then
      RBIN="$ROOT/bench/rust/target/release/pqb-rust"
      "$RBIN" --provenance > "$RUST_PROV"
      pqb_log "running RustCrypto KEM/sig sweep"
      while IFS=$'\t' read -r kind alg; do
        [ -z "$alg" ] && continue
        pqb_log "  rust $kind $alg"
        ERRF="$WORK/err.rust.$kind.$alg.txt"
        # shellcheck disable=SC2086
        if $TASKSET "$RBIN" --kind "$kind" --alg "$alg" \
            "${BENCH_SIZE_ARGS[@]}" >> "$KEMSIG_OUT" 2>"$ERRF"; then
          :
        else
          add_warn "rust harness failed for $kind $alg (see $ERRF)"
        fi
      done < <("$RBIN" --list)
    else
      add_warn "rust harness build failed (see $WORK/rust_build.log) — rustcrypto group skipped"
      echo '{"available":false,"reason":"cargo build failed (see rust_build.log in the run work dir)"}' > "$RUST_PROV"
    fi
  else
    add_warn "cargo not installed — rustcrypto measurement group skipped"
    echo '{"available":false,"reason":"Rust toolchain (cargo) not installed on this host"}' > "$RUST_PROV"
  fi

  # ---- aws-lc-rs primitive PRICING rows -----------------------------------
  # The primitives the rustls-awslc TLS handshakes actually execute
  # (implementation:"aws-lc-rs"). NOT an independent implementation — it
  # wraps the AWS-LC C library — measured solely so the rustls handshake
  # primitive sums are priced from the right code.
  if command -v cargo >/dev/null 2>&1; then
    pqb_log "building rustls harness for aws-lc-rs pricing rows"
    if (cd "$ROOT/bench/rust-tls" && cargo build --release --locked) >"$WORK/rust_tls_build.log" 2>&1; then
      RTBIN="$ROOT/bench/rust-tls/target/release/pqb-rust-tls"
      pqb_log "running aws-lc-rs primitive sweep"
      while IFS=$'\t' read -r kind alg; do
        [ -z "$alg" ] && continue
        pqb_log "  aws-lc-rs $kind $alg"
        ERRF="$WORK/err.awslc.$kind.$alg.txt"
        # shellcheck disable=SC2086
        if $TASKSET "$RTBIN" --kind "$kind" --alg "$alg" \
            "${BENCH_SIZE_ARGS[@]}" >> "$KEMSIG_OUT" 2>"$ERRF"; then
          :
        else
          add_warn "aws-lc-rs pricing row failed for $kind $alg (see $ERRF)"
        fi
      done < <("$RTBIN" --list-primitives)
    else
      add_warn "rust-tls build failed (see $WORK/rust_tls_build.log) — aws-lc-rs pricing rows skipped"
    fi
  fi
fi

# ---- TLS layer -------------------------------------------------------------
if [ "$DO_TLS" = 1 ]; then
  if [ -x "$ROOT/bench/tls/run_tls.sh" ]; then
    TLS_CONNS="$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('connections',1000))" \
                  "$(python3 "$ROOT/bench/lib/list_algs.py" tls "$ROOT/config.yaml")")"
    [ "$SMOKE" = 1 ] && TLS_CONNS=50
    pqb_log "running TLS handshake matrix ($TLS_CONNS handshakes/cell)"
    RUST_TLS_PROV="$WORK/rust_tls_provenance.json"
    if PQB_TASKSET="$TASKSET" PQB_RUSTLS_PROV="$RUST_TLS_PROV" "$ROOT/bench/tls/run_tls.sh" \
         --out "$TLS_OUT" --connections "$TLS_CONNS" >"$WORK/tls.log" 2>&1; then
      pqb_log "TLS layer done ($(grep -c '"label"' "$TLS_OUT" 2>/dev/null || echo 0) cells)"
    else
      add_warn "TLS layer failed or unavailable (see $WORK/tls.log) — continuing without it"
      TLS_OUT=""
    fi
  else
    pqb_warn "TLS harness not present yet — skipping (will be added)"
    TLS_OUT=""
  fi
fi

# ---- stop sampler, gather timing -------------------------------------------
kill "$SAMPLER_PID" 2>/dev/null || true
trap - EXIT
TS_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DURATION=$(( $(date +%s) - START_EPOCH ))
GOV_AFTER_END="$(pqb_get_governor)"

# ---- host facts ------------------------------------------------------------
collect_host_facts() {
  local cpu_brand="" ncpu="" ram="" os_pretty="" kernel
  kernel="$(uname -r)"
  if [ "$PQB_OS" = "macos" ]; then
    cpu_brand="$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
    ncpu="$(sysctl -n hw.ncpu 2>/dev/null)"
    ram="$(sysctl -n hw.memsize 2>/dev/null)"
    os_pretty="macOS $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
  else
    # aarch64 /proc/cpuinfo has no 'model name' line, so this grep misses; the
    # trailing `|| true` keeps `set -o pipefail` from aborting the run (errexit)
    # before the PQB_RPI_MODEL fallback below can supply the brand.
    cpu_brand="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || true)"
    [ -z "$cpu_brand" ] && cpu_brand="$PQB_RPI_MODEL"
    ncpu="$( (command -v nproc >/dev/null && nproc) || grep -c ^processor /proc/cpuinfo)"
    ram="$(( $(grep -m1 MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}') * 1024 ))"
    os_pretty="$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
  fi
  {
    echo "TOOL_VERSION=$TOOL_VERSION"
    echo "HOSTNAME=$HOST"
    echo "OS=$PQB_OS"
    echo "ARCH=$PQB_ARCH"
    echo "KERNEL=$kernel"
    echo "OS_PRETTY=\"$os_pretty\""
    echo "IS_RPI=$PQB_IS_RPI"
    echo "RPI_MODEL=\"$PQB_RPI_MODEL\""
    echo "CPU_BRAND=\"$cpu_brand\""
    echo "NCPU=$ncpu"
    echo "RAM_BYTES=$ram"
    echo "GOVERNOR_REQUESTED=$GOV_REQUESTED"
    echo "GOVERNOR_BEFORE=$GOV_BEFORE"
    echo "GOVERNOR_AFTER=$GOV_AFTER_END"
    echo "BENCH_CORE=$BENCH_CORE"
    echo "PINNED=$PINNED"
    echo "TASKSET_CMD=\"$TASKSET\""
    echo "CALIB_MODE=$CALIB_MODE"
    echo "TARGET_TIME_MS=$TARGET_TIME_MS"
    echo "MIN_SAMPLES=$MIN_SAMPLES"
    echo "MAX_ITERS=$MAX_ITERS"
    echo "REPS=$REPS"
    # warmup/timed_iters are single values only in fixed-count mode; in auto mode
    # they are chosen per-op and recorded in each operation's JSON instead.
    if [ "$CALIB_MODE" = "fixed" ]; then
      echo "WARMUP=$WARMUP"
      echo "ITERS=$ITERS"
    else
      echo "WARMUP="
      echo "ITERS="
    fi
    echo "CYCLES_MODE=$CYCLES_MODE"
    echo "CYCLES_AVAILABLE=$CYCLES_AVAILABLE"
    echo "CYCLES_REASON=\"$CYCLES_REASON\""
    echo "TS_START_UTC=$TS_START"
    echo "TS_END_UTC=$TS_END"
    echo "DURATION_S=$DURATION"
    echo "WARNINGS=\"$WARN_ACC\""
  } > "$META"
}
collect_host_facts

# ---- assemble final results JSON -------------------------------------------
OUT="$ROOT/results/${HOST}-${TS}.json"
python3 "$ROOT/bench/lib/assemble.py" \
  --meta "$META" --lock "$LOCK" --features "$FEATURES" \
  --kemsig "$KEMSIG_OUT" ${TLS_OUT:+--tls "$TLS_OUT"} \
  ${RUST_PROV:+--rust-provenance "$RUST_PROV"} \
  ${RUST_TLS_PROV:+--rust-tls-provenance "$RUST_TLS_PROV"} \
  --thermal "$THERMAL" --config "$ROOT/config.yaml" \
  --out "$OUT" >/dev/null

# ---- summary ---------------------------------------------------------------
echo
pqb_log "================ RUN COMPLETE ================"
python3 - "$OUT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
g=d["is_baseline_grade"]
print(f"  results: {sys.argv[1]}")
print(f"  host: {d['host']['cpu_brand']} ({d['host']['os_pretty']})")
print(f"  baseline-grade (reference platform: RPi5): {g}")
if not g:
    for r in d['baseline_grade_reasons']:
        print(f"     - {r}")
tt=d['thermal_trace']
print(f"  thermal: {tt.get('temp_c')}  throttling={tt.get('throttling_detected')}")
print(f"  kem algos: {sum(1 for x in d['kem'] if x.get('enabled'))} enabled / {len(d['kem'])}")
print(f"  sig algos: {sum(1 for x in d['sig'] if x.get('enabled'))} enabled / {len(d['sig'])}")
print(f"  cycles available: {d['run']['cycles_available']}")
PY
pqb_log "keep raw work dir? -> $WORK (safe to delete)"
