#!/usr/bin/env bash
# =============================================================================
# make check — READ-ONLY environment verification. Changes nothing; prints a
# per-platform install command for anything missing (never runs it — that is
# the opt-in `make deps`). Live probes only (openssl version, cargo --version):
# no stamp files, so an upgraded/removed tool can never be masked by a stale
# "installed" marker.
#
# Exit: 1 if a HARD requirement is missing (compiler, cmake, git, python3),
#       0 otherwise — warnings (old OpenSSL, missing Rust, missing Pi tools)
#       are loud but not fatal, because the harness degrades exactly as the
#       README documents (source-build fallback / skipped groups / non-
#       baseline-grade stamp).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=setup/lib_platform.sh
source "$HERE/setup/lib_platform.sh"
pqb_detect_platform
# test hooks (see also PQB_CHECK_FORCE_OPENSSL / PQB_TEST_OS_RELEASE): let the
# per-platform failure output be exercised on machines where it can't occur
[ -n "${PQB_TEST_OS:-}" ] && PQB_OS="$PQB_TEST_OS"

MISSING=0 WARNINGS=0

remedy() { # <package> -> platform-appropriate install hint
  case "$PQB_OS" in
    macos) echo "brew install $1" ;;
    linux) if command -v apt-get >/dev/null 2>&1; then echo "sudo apt-get install -y $1"
           else echo "install '$1' via your distribution's package manager"; fi ;;
    *) echo "install '$1' for your platform" ;;
  esac
}

ok()   { printf '[check] %-9s ok    %s\n' "$1" "$2"; }
warn() { printf '[check] %-9s WARN  %s\n' "$1" "$2"; WARNINGS=$((WARNINGS+1)); }
miss() { printf '[check] %-9s MISSING   -> %s\n' "$1" "$2"; MISSING=$((MISSING+1)); }

# ---- hard requirements ------------------------------------------------------
if command -v cc >/dev/null 2>&1; then
  ok cc "$(cc --version 2>/dev/null | head -1)"
else
  miss cc "$(remedy "build-essential (Linux) / Xcode command-line tools (macOS)")"
fi
if command -v cmake >/dev/null 2>&1; then
  ok cmake "$(cmake --version | head -1)"
else
  miss cmake "$(remedy cmake)"
fi
if command -v git >/dev/null 2>&1; then
  ok git "$(git --version)"
else
  miss git "$(remedy git)"
fi
if command -v python3 >/dev/null 2>&1; then
  ok python3 "$(python3 --version 2>&1)"
else
  miss python3 "$(remedy python3)"
fi

# ---- OpenSSL --------------------------------------------------------------
# Two distinct requirements that MUST NOT be conflated (the Fedora lesson:
# the openssl BINARY was present, `openssl version` passed, and the liboqs
# cmake build then failed with 'Could NOT find OpenSSL' because the
# DEVELOPMENT FILES — headers + linkable libcrypto — are a separate package):
#   1. which OpenSSL the build will use: the SAME candidate walk setup.sh
#      uses (keg -> PATH -> system). We probe that resolution, not an
#      independent search — a check that passes while the build links a
#      different OpenSSL is worse than no check. (This is also why we don't
#      use plain pkg-config: the pinned keg-only openssl@3.5 on macOS is
#      deliberately NOT in the pkgconfig path.)
#   2. whether that candidate's prefix has the dev files: verified by an
#      actual compile-and-link probe against the prefix, exactly what the
#      cmake build will attempt.
# PQB_CHECK_FORCE_OPENSSL forces the candidate (test hook, used to exercise
# these failure paths on machines where a real one can't occur).
dev_pkg_hint() {
  case "$PQB_OS" in
    macos) echo "brew install openssl@3.5" ;;
    linux) case "$(pqb_linux_family)" in
             debian) echo "sudo apt-get install -y libssl-dev" ;;
             fedora) echo "sudo dnf install -y openssl-devel" ;;
             arch)   echo "sudo pacman -S openssl" ;;
             suse)   echo "sudo zypper install libopenssl-devel" ;;
             *)      echo "install your distribution's OpenSSL development package (headers + libcrypto)" ;;
           esac ;;
    *) echo "install OpenSSL development files for your platform" ;;
  esac
}
probe_openssl_dev() { # <prefix> -> 0 if headers + libcrypto link at that prefix
  local prefix="$1" t; t="$(mktemp -d)"
  cat > "$t/p.c" <<'EOF'
#include <openssl/evp.h>
int main(void) { return EVP_MD_fetch ? 0 : 1; }
EOF
  cc "$t/p.c" -I"$prefix/include" -L"$prefix/lib" -L"$prefix/lib64" \
     -lcrypto -o "$t/p" 2>"$t/err"
  local rc=$?
  rm -rf "$t"
  return $rc
}

OSSL_FOUND="" OSSL_VER="" OSSL_NOTE=""
if [ -n "${PQB_CHECK_FORCE_OPENSSL:-}" ]; then
  CANDS=("$PQB_CHECK_FORCE_OPENSSL")
else
  CANDS=(/opt/homebrew/opt/openssl@3.5/bin/openssl
         "$(command -v openssl || true)"
         /opt/homebrew/opt/openssl@3/bin/openssl /usr/bin/openssl)
fi
for cand in "${CANDS[@]}"; do
  [ -n "$cand" ] && [ -x "$cand" ] || continue
  v="$("$cand" version 2>/dev/null || true)"
  case "$v" in
    OpenSSL\ 3.5.*) OSSL_FOUND="$cand"; OSSL_VER="$v"; OSSL_NOTE="pinned 3.5.x line"; break ;;
    OpenSSL\ *) if [ -z "$OSSL_FOUND" ]; then OSSL_FOUND="$cand"; OSSL_VER="$v"; OSSL_NOTE="not the pinned 3.5.x line"; fi ;;
    LibreSSL*) : ;;  # LibreSSL masquerading as openssl (macOS /usr/bin) — skip
  esac
done

if [ -n "$OSSL_FOUND" ]; then
  maj="${OSSL_VER#OpenSSL }"; maj="${maj%% *}"
  OSSL_PREFIX_GUESS="$(dirname "$(dirname "$OSSL_FOUND")")"
  case "$maj" in
    3.5.*|3.[6-9].*|[4-9].*)
      # the build will use this prefix -> its dev files are REQUIRED
      if probe_openssl_dev "$OSSL_PREFIX_GUESS"; then
        case "$maj" in
          3.5.*) ok openssl "$OSSL_VER ($OSSL_NOTE) at $OSSL_FOUND — headers + libcrypto link OK" ;;
          *) warn openssl "$OSSL_VER at $OSSL_FOUND (dev files OK) — usable but $OSSL_NOTE; cross-machine TLS comparisons should stay on 3.5.x" ;;
        esac
      else
        miss "openssl-dev" "$(dev_pkg_hint)   [the build will use $OSSL_PREFIX_GUESS ($OSSL_VER) and needs its DEVELOPMENT files — the binary alone is not enough: liboqs/oqs-provider compile and link against libcrypto]"
      fi
      ;;
    *)
      warn openssl "$OSSL_VER at $OSSL_FOUND — older than 3.5: setup will SOURCE-BUILD the pinned OpenSSL 3.5.x into vendor/ (+15-30 min; needs perl). The native TLS phase matrix then still runs — it degrades only if the source build is skipped."
      command -v perl >/dev/null 2>&1 || miss perl "$(remedy perl)   [required for the OpenSSL source build]"
      ;;
  esac
else
  warn openssl "no real OpenSSL found (only LibreSSL or nothing) — setup will SOURCE-BUILD the pinned 3.5.x (+15-30 min; needs perl). Faster: $(dev_pkg_hint)"
  command -v perl >/dev/null 2>&1 || miss perl "$(remedy perl)   [required for the OpenSSL source build]"
fi

# ---- Rust: run cargo for real — this exercises rustup toolchain RESOLUTION,
# ---- the exact thing that silently broke under sudo on the Pi --------------
if cargo --version >/dev/null 2>&1; then
  ok rust "$(cargo --version) (toolchain resolves)"
else
  warn rust "cargo not found or toolchain does not resolve — the RustCrypto and rustls groups (2 of 4) will be SKIPPED. Install: https://rustup.rs (or 'make deps RUST=1')"
fi

# ---- Linux / Pi niceties (baseline-grade prerequisites) ---------------------
if [ "$PQB_OS" = "linux" ]; then
  command -v taskset >/dev/null 2>&1 && ok taskset "core pinning available" \
    || warn taskset "no taskset — runs will be unpinned (not baseline-grade). $(remedy util-linux)"
  CPUPOWER_PKG=linux-cpupower
  [ "$(pqb_linux_family)" = fedora ] && CPUPOWER_PKG=kernel-tools
  command -v cpupower >/dev/null 2>&1 && ok cpupower "governor control available" \
    || warn cpupower "no cpupower — performance governor cannot be set. $(remedy "$CPUPOWER_PKG")"
  if [ "$PQB_IS_RPI" = 1 ]; then
    command -v vcgencmd >/dev/null 2>&1 && ok vcgencmd "thermal/throttle telemetry available" \
      || warn vcgencmd "no vcgencmd — thermal trace and throttle detection unavailable on this Pi"
  fi
fi

echo
if [ "$MISSING" -gt 0 ]; then
  echo "[check] $MISSING required item(s) missing — run the commands above, or 'make deps'."
  exit 1
fi
if [ "$WARNINGS" -gt 0 ]; then
  echo "[check] environment usable with $WARNINGS warning(s) above (degradations are recorded in the results JSON)."
else
  echo "[check] environment fully ready."
fi
