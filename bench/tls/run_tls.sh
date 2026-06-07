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
OSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl@3 2>/dev/null || echo /usr)}"
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
  # server key + CSR + cert signed by CA
  "$OSSL" genpkey -algorithm "$alg" $prov -out "$sv_key" >/dev/null 2>&1 || return 1
  "$OSSL" req -new -key "$sv_key" $prov -out "$sv_csr" -subj "/CN=localhost" >/dev/null 2>&1 || return 1
  "$OSSL" x509 -req -in "$sv_csr" -CA "$ca_crt" -CAkey "$ca_key" $prov \
      -out "$sv_crt" -days 3650 -CAcreateserial >/dev/null 2>&1 || return 1
  return 0
}

# ---- read config -----------------------------------------------------------
TLS_JSON="$(python3 "$ROOT/bench/lib/list_algs.py" tls "$ROOT/config.yaml")"
read_list() { python3 -c "import json,sys; print('\n'.join(json.loads(sys.argv[1]).get(sys.argv[2],[])))" "$TLS_JSON" "$1"; }
BASE_KEM="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['baseline']['kem_group'])" "$TLS_JSON")"
BASE_SIG="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['baseline']['sig_alg'])" "$TLS_JSON")"

# ---- generate certs --------------------------------------------------------
declare -a SIG_OK_ALGS=()
# classical baseline cert (always)
if gen_cert "$BASE_SIG" "base_$BASE_SIG"; then
  pqb_log "generated baseline cert ($BASE_SIG)"
else
  pqb_err "failed to generate classical baseline cert ($BASE_SIG) — TLS layer cannot run"
  echo '{"available":false,"reason":"baseline cert generation failed"}' > "$OUT"; exit 0
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

# cert path helpers
ca_for()  { case "$1" in "$BASE_SIG") echo "$PKI/base_${BASE_SIG}_ca.pem";; *) echo "$PKI/pq_${1}_ca.pem";; esac; }
crt_for() { case "$1" in "$BASE_SIG") echo "$PKI/base_${BASE_SIG}_server.pem";; *) echo "$PKI/pq_${1}_server.pem";; esac; }
key_for() { case "$1" in "$BASE_SIG") echo "$PKI/base_${BASE_SIG}_server.key";; *) echo "$PKI/pq_${1}_server.key";; esac; }

# run one matrix cell -> appends JSON object to $ROWS file
run_cell() {
  local kem="$1" sig="$2"
  local label="${kem}+${sig}"
  # shellcheck disable=SC2086
  $TASKSET "$BENCH" --group "$kem" --ca "$(ca_for "$sig")" \
      --cert "$(crt_for "$sig")" --key "$(key_for "$sig")" \
      --connections "$CONNS" --warmup "$WARMUP" --label "$label" 2>>"$PKI/bench_tls.err"
}

ROWS="$PKI/rows.jsonl"; : > "$ROWS"

# baseline row always first
pqb_log "TLS baseline: $BASE_KEM + $BASE_SIG ($CONNS handshakes)"
run_cell "$BASE_KEM" "$BASE_SIG" >> "$ROWS" || pqb_warn "baseline TLS cell failed"

# PQ matrix: (kem_groups x sig_algs) — only cells whose cert exists
if [ "$HAVE_OQS" = 1 ] && [ "${#SIG_OK_ALGS[@]}" -gt 0 ]; then
  while IFS= read -r kem; do
    [ -z "$kem" ] && continue
    for sig in "${SIG_OK_ALGS[@]}"; do
      pqb_log "TLS cell: $kem + $sig"
      run_cell "$kem" "$sig" >> "$ROWS" || pqb_warn "cell $kem+$sig failed"
    done
  done < <(read_list kem_groups)
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
