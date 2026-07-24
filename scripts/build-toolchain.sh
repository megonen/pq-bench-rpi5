#!/usr/bin/env bash
# =============================================================================
# make build — C toolchain + bench binaries + both Rust harnesses.
#
# Skip decisions use REAL checks, never stamp files: the C toolchain rebuild
# is skipped only when versions.lock exists AND the liboqs library AND the
# oqs-provider module it records are on disk AND the OpenSSL binary it records
# still exists and still reports the recorded version (so upgrading/removing
# OpenSSL forces a rebuild instead of being silently masked). Bench binaries
# use their Makefiles' own file-based dependency tracking; cargo tracks its
# own inputs.
#
# The Rust harnesses are ALWAYS built as the invoking (non-root) user: cargo
# under root leaves root-owned target/ trees, so we refuse.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
# shellcheck source=setup/lib_platform.sh
source "$HERE/setup/lib_platform.sh"
pqb_detect_platform

LOCK="$HERE/setup/versions.lock"

toolchain_ok() {
  [ -f "$LOCK" ] || { echo "no versions.lock"; return 1; }
  # shellcheck disable=SC1090
  source "$LOCK"
  ls "$HERE"/vendor/install/lib/liboqs.* >/dev/null 2>&1 || { echo "liboqs library missing"; return 1; }
  [ -n "${OQSPROVIDER_MODULE:-}" ] && [ -f "$OQSPROVIDER_MODULE" ] || { echo "oqs-provider module missing"; return 1; }
  [ -n "${OPENSSL_BIN:-}" ] && [ -x "$OPENSSL_BIN" ] || { echo "recorded OpenSSL binary gone"; return 1; }
  local live="system:$("$OPENSSL_BIN" version 2>/dev/null | awk '{print $2}')"
  case "${OPENSSL_COMMIT:-}" in
    system:*) [ "$live" = "$OPENSSL_COMMIT" ] || { echo "OpenSSL changed: lock=$OPENSSL_COMMIT live=$live"; return 1; } ;;
  esac
  return 0
}

if reason="$(toolchain_ok)"; then
  pqb_log "C toolchain present and consistent with versions.lock — skipping setup.sh (delete vendor/ or versions.lock to force)"
else
  pqb_log "building C toolchain (${reason:-first build})"
  ./setup/setup.sh all
fi

# shellcheck disable=SC1090
source "$LOCK"
pqb_log "building bench_pq / bench_tls"
make -C bench/kem_sig \
  LIBOQS_PREFIX="${PREFIX:-$HERE/vendor/install}" \
  OPENSSL_PREFIX="${OPENSSL_PREFIX:-/usr}" \
  BENCH_CFLAGS="${BENCH_CFLAGS:--O3}"
make -C bench/tls OPENSSL_PREFIX="${OPENSSL_PREFIX:-/usr}"

if cargo --version >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    pqb_err "refusing to run cargo as root (root-owned target/ trees break later user builds)."
    pqb_err "Run 'make build' as your normal user; sudo is only needed for the run itself."
    exit 1
  fi
  pqb_log "building Rust harnesses (cargo --release --locked, as $(id -un))"
  (cd bench/rust && cargo build --release --locked)
  (cd bench/rust-tls && cargo build --release --locked)
else
  pqb_warn "cargo not available — Rust harnesses not built; the rustcrypto/aws-lc-rs/rustls-awslc groups will be skipped (recorded in results)"
fi
pqb_log "build complete"
