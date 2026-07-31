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
  if ! ./setup/setup.sh all; then
    pqb_err "C toolchain build FAILED — stopping here. Fix the error above"
    pqb_err "(commonly: missing OpenSSL DEVELOPMENT files — run 'make check')."
    pqb_err "Nothing further was attempted, so any later error you may have"
    pqb_err "seen previously (e.g. 'cannot find -loqs') was a symptom of this."
    exit 1
  fi
fi

# ---- HARD GUARD: only the vendored, pinned liboqs/oqs-provider may be used --
# A system liboqs (e.g. a distro liboqs-devel) could build SILENTLY and every
# measurement would then run against an unpinned library — destroying the
# comparability the vendoring exists to guarantee. Refuse before any bench
# binary is compiled. (bench/kem_sig/Makefile enforces the same guard, so the
# direct `run.sh` path is protected too.)
if ! ls "$HERE"/vendor/install/lib/liboqs.* >/dev/null 2>&1 \
   || [ ! -f "$HERE/vendor/install/include/oqs/oqs.h" ]; then
  pqb_err "pinned vendored liboqs not found. Looked for BOTH of:"
  pqb_err "  $HERE/vendor/install/include/oqs/oqs.h"
  pqb_err "  $HERE/vendor/install/lib/liboqs.*"
  pqb_err "Inspect the actual layout: ls $HERE/vendor/install"
  pqb_err "- nothing there: the toolchain build failed — scroll up for the original error"
  pqb_err "- a lib64/ directory: built before the layout was pinned"
  pqb_err "  (-DCMAKE_INSTALL_LIBDIR=lib) — run 'make distclean && make build'"
  pqb_err "Do NOT install a distro liboqs to work around this: linking a system"
  pqb_err "liboqs is refused — unpinned versions are not comparable with the"
  pqb_err "published baselines, and the pinned oqs-provider expects exactly the"
  pqb_err "pinned liboqs' headers."
  exit 1
fi
# shellcheck disable=SC1090
source "$LOCK"
case "${OQSPROVIDER_MODULE:-}" in
  "$HERE"/vendor/*) [ -f "$OQSPROVIDER_MODULE" ] || { pqb_err "oqs-provider module recorded in versions.lock is missing ($OQSPROVIDER_MODULE) — run 'make build'"; exit 1; } ;;
  "") pqb_err "versions.lock records no oqs-provider module — run 'make build'"; exit 1 ;;
  *) pqb_err "versions.lock points at a NON-VENDORED oqs-provider ($OQSPROVIDER_MODULE) — refusing: only the pinned, vendored provider may be used"; exit 1 ;;
esac

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
