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

# ---- OpenSSL: same candidate walk setup.sh uses; LibreSSL is not OpenSSL ----
OSSL_FOUND="" OSSL_VER="" OSSL_NOTE=""
for cand in /opt/homebrew/opt/openssl@3.5/bin/openssl \
            "$(command -v openssl || true)" \
            /opt/homebrew/opt/openssl@3/bin/openssl /usr/bin/openssl; do
  [ -x "$cand" ] || continue
  v="$("$cand" version 2>/dev/null || true)"
  case "$v" in
    OpenSSL\ 3.5.*) OSSL_FOUND="$cand"; OSSL_VER="$v"; OSSL_NOTE="pinned 3.5.x line"; break ;;
    OpenSSL\ *) if [ -z "$OSSL_FOUND" ]; then OSSL_FOUND="$cand"; OSSL_VER="$v"; OSSL_NOTE="not the pinned 3.5.x line"; fi ;;
    LibreSSL*) : ;;  # LibreSSL masquerading as openssl (macOS /usr/bin) — skip
  esac
done
if [ -n "$OSSL_FOUND" ]; then
  maj="${OSSL_VER#OpenSSL }"; maj="${maj%% *}"
  case "$maj" in
    3.5.*) ok openssl "$OSSL_VER ($OSSL_NOTE) at $OSSL_FOUND" ;;
    3.[6-9].*|[4-9].*) warn openssl "$OSSL_VER at $OSSL_FOUND — usable but $OSSL_NOTE; cross-machine TLS comparisons should stay on 3.5.x ($(remedy openssl@3.5))" ;;
    *) warn openssl "$OSSL_VER at $OSSL_FOUND — older than 3.5: setup will SOURCE-BUILD OpenSSL 3.5.x (+15-30 min). To use a system one: $(remedy "openssl@3.5 (macOS) / upgrade to Debian 13")" ;;
  esac
else
  warn openssl "no real OpenSSL found (only LibreSSL or nothing) — setup will SOURCE-BUILD OpenSSL 3.5.x (+15-30 min). Faster: $(remedy openssl@3.5)"
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
  command -v cpupower >/dev/null 2>&1 && ok cpupower "governor control available" \
    || warn cpupower "no cpupower — performance governor cannot be set. $(remedy linux-cpupower)"
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
