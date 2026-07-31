#!/usr/bin/env bash
# =============================================================================
# run_tls.sh — generate PKI and run the TLS 1.3 (KEM-group x signature) matrix.
#
# Always benchmarks the classical Logos baseline (X25519 key exchange + Ed25519
# server auth) using stock OpenSSL. PQ rows additionally require oqs-provider to
# be loadable; if it is not present we record those rows as unavailable (with a
# reason) rather than failing — so this still smoke-tests cleanly on a dev box.
#
#   ./run_tls.sh --out tls.json --connections 1000
#
# Honors $PQB_TASKSET (a taskset/numactl prefix) to pin bench_tls to a core.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=setup/lib_platform.sh
source "$ROOT/setup/lib_platform.sh"
LOCK="$ROOT/setup/versions.lock"
# shellcheck disable=SC1090
[ -f "$LOCK" ] && source "$LOCK" || true
pqb_detect_platform
# set -e deaths must never be silent (see run.sh)
set -E  # errtrace: without it the ERR trap does not fire inside functions
trap 'pqb_err "run_tls.sh aborted at line $LINENO while running: $BASH_COMMAND"' ERR

OUT=""; CONNS=1000; WARMUP=20
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift ;;
    --connections) CONNS="$2"; shift ;;
    --warmup) WARMUP="$2"; shift ;;
    *) pqb_err "unknown arg: $1"; exit 2 ;;
  esac
  shift
done
[ -n "$OUT" ] || { pqb_err "--out required"; exit 2; }

TASKSET="${PQB_TASKSET:-}"

# ---- choose the OpenSSL that has the provider ------------------------------
OSSL="${OPENSSL_BIN:-$(command -v openssl)}"
OSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl@3.5 2>/dev/null || echo /usr)}"
PROV_MODULE="${OQSPROVIDER_MODULE:-}"
PROV_ARGS=""
HAVE_OQS=0
if [ -n "$PROV_MODULE" ] && [ -f "$PROV_MODULE" ]; then
  export OPENSSL_MODULES="$(dirname "$PROV_MODULE")"
  if "$OSSL" list -providers -provider oqsprovider -provider default >/dev/null 2>&1; then
    PROV_ARGS="-provider oqsprovider -provider default"
    HAVE_OQS=1
    pqb_log "oqs-provider available: $PROV_MODULE"
  fi
fi
[ "$HAVE_OQS" = 0 ] && pqb_warn "oqs-provider not available — PQ TLS rows will be marked unavailable (classical baseline still runs)"

# ---- build the harness -----------------------------------------------------
make -C "$HERE" OPENSSL_PREFIX="$OSSL_PREFIX" >/dev/null
BENCH="$HERE/bench_tls"
[ -n "$TASKSET" ] && export OPENSSL_MODULES="${OPENSSL_MODULES:-}"

# ---- PKI workspace ---------------------------------------------------------
PKI="$HERE/pki"; rm -rf "$PKI"; mkdir -p "$PKI"

# gen_cert <sig_alg> <out_prefix> [provider]  -> CA + server cert/key of that alg
gen_cert() {
  local alg="$1" pfx="$2" prov="${3:-}"
  local ca_key="$PKI/${pfx}_ca.key" ca_crt="$PKI/${pfx}_ca.pem"
  local sv_key="$PKI/${pfx}_server.key" sv_csr="$PKI/${pfx}_server.csr" sv_crt="$PKI/${pfx}_server.pem"
  # CA
  "$OSSL" req -x509 -new -newkey "$alg" -nodes $prov \
      -keyout "$ca_key" -out "$ca_crt" -days 3650 \
      -subj "/CN=PQB Test CA ($alg)" >/dev/null 2>&1 || return 1
  # server key + CSR + cert signed by CA. SAN is REQUIRED by webpki (the
  # rustls verifier rejects CN-only certs); OpenSSL doesn't mind, so the same
  # certs serve every stack. -copy_extensions carries the SAN into the cert.
  "$OSSL" genpkey -algorithm "$alg" $prov -out "$sv_key" >/dev/null 2>&1 || return 1
  "$OSSL" req -new -key "$sv_key" $prov -out "$sv_csr" -subj "/CN=localhost" \
      -addext "subjectAltName = DNS:localhost" >/dev/null 2>&1 || return 1
  "$OSSL" x509 -req -in "$sv_csr" -CA "$ca_crt" -CAkey "$ca_key" $prov \
      -copy_extensions copyall \
      -out "$sv_crt" -days 3650 -CAcreateserial >/dev/null 2>&1 || return 1
  return 0
}

# ---- read config -----------------------------------------------------------
TLS_JSON="$(python3 "$ROOT/bench/lib/list_algs.py" tls "$ROOT/config.yaml")"
read_list() { python3 -c "import json,sys; print('\n'.join(json.loads(sys.argv[1]).get(sys.argv[2],[]) or []))" "$TLS_JSON" "$1"; }
read_native_list() { python3 -c "import json,sys; print('\n'.join(((json.loads(sys.argv[1]).get('native') or {}).get(sys.argv[2])) or []))" "$TLS_JSON" "$1"; }
BASE_KEM="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['baseline']['kem_group'])" "$TLS_JSON")"
BASE_SIG="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['baseline']['sig_alg'])" "$TLS_JSON")"

# ---- native PQC availability probe -----------------------------------------
# The openssl-native matrix needs OpenSSL's own ML-KEM TLS groups (>= 3.5).
NATIVE_OK=0
if "$OSSL" list -tls-groups 2>/dev/null | tr ':' '\n' | grep -qi '^mlkem'; then
  NATIVE_OK=1
  pqb_log "native PQC TLS available in $("$OSSL" version | awk '{print $1, $2}')"
else
  pqb_warn "this OpenSSL exposes no native MLKEM TLS groups — openssl-native matrix skipped"
fi

# ---- generate certs --------------------------------------------------------
declare -a SIG_OK_ALGS=()      # oqs-provider PQ sig algs with a working cert
declare -a NATIVE_SIG_OK=()    # native PQ sig algs with a working cert
# classical baseline cert (always; generated by the native openssl, used by the
# baseline + every phase0 cell)
if gen_cert "$BASE_SIG" "base_$BASE_SIG"; then
  pqb_log "generated baseline cert ($BASE_SIG)"
else
  pqb_err "failed to generate classical baseline cert ($BASE_SIG) — TLS layer cannot run"
  echo '{"available":false,"reason":"baseline cert generation failed"}' > "$OUT"; exit 0
fi
# native PQ certs: generated by native OpenSSL >= 3.5 itself (NOT oqs-provider —
# different code path, potentially different encodings; phase2-native must be
# native end to end)
if [ "$NATIVE_OK" = 1 ]; then
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    if gen_cert "$s" "native_$s"; then
      NATIVE_SIG_OK+=("$s"); pqb_log "generated native PQ cert ($s)"
    else
      pqb_warn "could not generate NATIVE cert for sig alg '$s' (skipping)"
    fi
  done < <(read_native_list pq_sigs)
fi
if [ "$HAVE_OQS" = 1 ]; then
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    if gen_cert "$s" "pq_$s" "$PROV_ARGS"; then
      SIG_OK_ALGS+=("$s"); pqb_log "generated PQ cert ($s)"
    else
      pqb_warn "could not generate cert for sig alg '$s' (skipping)"
    fi
  done < <(read_list sig_algs)
fi

# Migration-phase classification for a (kem_group, sig_alg) cell:
#   baseline = classical KEM group + classical signature (what Logos runs today)
#   phase0   = PQ or hybrid KEM group + CLASSICAL signature (HNDL protection)
#   phase2   = PQ signature (regardless of group)
phase_for() {
  local kem_l sig_l pq_kem=0
  kem_l="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  sig_l="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  case "$kem_l" in
    *mlkem*|*kyber*|*frodo*|*hqc*|*bike*|*ntru*|*mceliece*) pq_kem=1 ;;
  esac
  case "$sig_l" in
    ed25519|ed448|ecdsa*|rsa*|ecdsap*)
      if [ "$pq_kem" = 1 ]; then echo phase0; else echo baseline; fi ;;
    *) echo phase2 ;;
  esac
}

# run one matrix cell -> appends JSON object to $ROWS file
#   run_cell <implementation> <cert-prefix> <kem-group> <sig-alg>
run_cell() {
  local impl="$1" pfx="$2" kem="$3" sig="$4"
  local label="${kem}+${sig}"
  # shellcheck disable=SC2086
  $TASKSET "$BENCH" --group "$kem" --ca "$PKI/${pfx}_ca.pem" \
      --cert "$PKI/${pfx}_server.pem" --key "$PKI/${pfx}_server.key" \
      --connections "$CONNS" --warmup "$WARMUP" --label "$label" \
      --sig-alg "$sig" --phase "$(phase_for "$kem" "$sig")" \
      --implementation "$impl" 2>>"$PKI/bench_tls.err"
}

ROWS="$PKI/rows.jsonl"; : > "$ROWS"

# ---- baseline: classical pair, measured NATIVE (no provider involved) ------
pqb_log "TLS baseline (openssl-native): $BASE_KEM + $BASE_SIG ($CONNS handshakes)"
run_cell openssl-native "base_$BASE_SIG" "$BASE_KEM" "$BASE_SIG" >> "$ROWS" \
  || pqb_warn "baseline TLS cell failed"

# ---- openssl-native matrix -------------------------------------------------
if [ "$NATIVE_OK" = 1 ]; then
  NATIVE_CLASSICAL="$(python3 -c "import json,sys;print((json.loads(sys.argv[1]).get('native') or {}).get('classical_sig',''))" "$TLS_JSON")"
  # phase0: hybrid + pure PQ groups with the CLASSICAL certificate (HNDL)
  while IFS= read -r kem; do
    [ -z "$kem" ] && continue
    pqb_log "TLS native phase0: $kem + $NATIVE_CLASSICAL"
    run_cell openssl-native "base_$NATIVE_CLASSICAL" "$kem" "$NATIVE_CLASSICAL" >> "$ROWS" \
      || pqb_warn "native cell $kem+$NATIVE_CLASSICAL failed"
  done < <(read_native_list hybrid_groups; read_native_list pure_groups)
  # phase2: X25519MLKEM768 + pure groups x native PQ sigs
  if [ "${#NATIVE_SIG_OK[@]}" -gt 0 ]; then
    while IFS= read -r kem; do
      [ -z "$kem" ] && continue
      for sig in "${NATIVE_SIG_OK[@]}"; do
        pqb_log "TLS native phase2: $kem + $sig"
        run_cell openssl-native "native_$sig" "$kem" "$sig" >> "$ROWS" \
          || pqb_warn "native cell $kem+$sig failed"
      done
    done < <(echo X25519MLKEM768; read_native_list pure_groups)
  fi
fi

# ---- oqs-provider matrix: (kem_groups x sig_algs) — only cells whose cert
# exists. Overlapping ML-DSA cells are deliberate (native-vs-provider delta);
# the falcon/sphincs cells exist ONLY here (draft TLS codepoints).
if [ "$HAVE_OQS" = 1 ] && [ "${#SIG_OK_ALGS[@]}" -gt 0 ]; then
  while IFS= read -r kem; do
    [ -z "$kem" ] && continue
    for sig in "${SIG_OK_ALGS[@]}"; do
      pqb_log "TLS cell (oqs-provider): $kem + $sig"
      run_cell oqs-provider "pq_$sig" "$kem" "$sig" >> "$ROWS" \
        || pqb_warn "cell $kem+$sig failed"
    done
  done < <(read_list kem_groups)
fi

# ---- rustls + aws-lc-rs matrix (implementation: rustls-awslc) ---------------
# Same phase structure, same in-memory methodology (pqb-rust-tls mirrors
# bench_tls.c). Reuses the SAME PEM certs: base_* for baseline/phase0 and the
# NATIVE OpenSSL-generated ML-DSA certs for phase2 (webpki needs the SAN that
# gen_cert now adds). Skipped gracefully without cargo.
RUSTLS_BIN="$ROOT/bench/rust-tls/target/release/pqb-rust-tls"
if command -v cargo >/dev/null 2>&1; then
  pqb_log "building rustls harness (cargo build --release --locked)"
  if (cd "$ROOT/bench/rust-tls" && cargo build --release --locked) >"$PKI/rustls_build.log" 2>&1; then
    :
  else
    pqb_warn "rustls harness build failed (see $PKI/rustls_build.log) — rustls-awslc matrix skipped"
    RUSTLS_BIN=""
  fi
else
  pqb_warn "cargo not installed — rustls-awslc TLS matrix skipped"
  RUSTLS_BIN=""
fi
if [ -n "$RUSTLS_BIN" ] && [ -x "$RUSTLS_BIN" ]; then
  [ -n "${PQB_RUSTLS_PROV:-}" ] && "$RUSTLS_BIN" --provenance > "$PQB_RUSTLS_PROV"
  read_rustls_list() { python3 -c "import json,sys; print('\n'.join(((json.loads(sys.argv[1]).get('rustls') or {}).get(sys.argv[2])) or []))" "$TLS_JSON" "$1"; }
  RUSTLS_CLASSICAL="$(python3 -c "import json,sys;print((json.loads(sys.argv[1]).get('rustls') or {}).get('classical_sig',''))" "$TLS_JSON")"
  run_rustls_cell() {  # <cert-prefix> <kem-group> <sig-alg>
    local pfx="$1" kem="$2" sig="$3"
    local label="${kem}+${sig}"
    # shellcheck disable=SC2086
    $TASKSET "$RUSTLS_BIN" --group "$kem" --ca "$PKI/${pfx}_ca.pem" \
        --cert "$PKI/${pfx}_server.pem" --key "$PKI/${pfx}_server.key" \
        --connections "$CONNS" --warmup "$WARMUP" --label "$label" \
        --sig-alg "$sig" --phase "$(phase_for "$kem" "$sig")" 2>>"$PKI/bench_tls.err"
  }
  pqb_log "TLS rustls baseline: X25519 + $BASE_SIG"
  run_rustls_cell "base_$BASE_SIG" X25519 "$BASE_SIG" >> "$ROWS" \
    || pqb_warn "rustls baseline cell failed"
  while IFS= read -r kem; do
    [ -z "$kem" ] && continue
    pqb_log "TLS rustls phase0: $kem + $RUSTLS_CLASSICAL"
    run_rustls_cell "base_$RUSTLS_CLASSICAL" "$kem" "$RUSTLS_CLASSICAL" >> "$ROWS" \
      || pqb_warn "rustls cell $kem+$RUSTLS_CLASSICAL failed"
  done < <(read_rustls_list hybrid_groups; read_rustls_list pure_groups)
  if [ "${#NATIVE_SIG_OK[@]}" -gt 0 ]; then
    while IFS= read -r kem; do
      [ -z "$kem" ] && continue
      for sig in "${NATIVE_SIG_OK[@]}"; do
        pqb_log "TLS rustls phase2: $kem + $sig"
        run_rustls_cell "native_$sig" "$kem" "$sig" >> "$ROWS" \
          || pqb_warn "rustls cell $kem+$sig failed"
      done
    done < <(echo X25519MLKEM768; read_rustls_list pure_groups)
  else
    pqb_warn "no native ML-DSA certs — rustls phase2 cells skipped"
  fi
  # SLH-DSA's absence from this stack is a FINDING, recorded in-data: across
  # both production stacks (rustls/aws-lc-rs here, native OpenSSL above —
  # draft TLS codepoints), SLH-DSA in TLS 1.3 exists only in the experimental
  # oqs-provider.
  printf '%s\n' '{"label":"X25519MLKEM768+SLH-DSA-SHA2-128f","group":"X25519MLKEM768","sig_alg":"SLH-DSA-SHA2-128f","phase":"phase2","implementation":"rustls-awslc","unstable_features":false,"enabled":false,"have_oqs_provider":false,"reason":"SLH-DSA is absent from rustls/aws-lc-rs entirely; native OpenSSL cannot negotiate it either (TLS codepoints still draft) - across both production stacks SLH-DSA in TLS exists only in the experimental oqs-provider"}' >> "$ROWS"
fi

# ---- assemble tls.json -----------------------------------------------------
python3 - "$ROWS" "$OUT" "$HAVE_OQS" "$BASE_KEM" "$BASE_SIG" <<'PY'
import json,sys
rows_path, out_path, have_oqs, base_kem, base_sig = sys.argv[1:6]
rows=[]
with open(rows_path) as f:
    for line in f:
        line=line.strip()
        if line:
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: pass
out={
  "available": True,
  "have_oqs_provider": have_oqs=="1",
  "baseline": {"kem_group": base_kem, "sig_alg": base_sig, "label": f"{base_kem}+{base_sig}"},
  "matrix": rows,
}
json.dump(out, open(out_path,"w"), indent=2)
print(f"wrote {out_path}: {len(rows)} cells (have_oqs={have_oqs})")
PY
