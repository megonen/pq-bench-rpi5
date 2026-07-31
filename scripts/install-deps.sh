#!/usr/bin/env bash
# =============================================================================
# make deps — the OPT-IN installer (make check never installs anything).
#   macOS:         brew install of the missing formulae only
#   Debian-family: the apt package set (via lib_platform.sh)
#   generic Linux: prints the list and exits 1 — we won't guess your package
#                  manager
# Rust is only installed with explicit consent:  make deps RUST=1
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=setup/lib_platform.sh
source "$HERE/setup/lib_platform.sh"
pqb_detect_platform

case "$PQB_OS" in
  macos)
    command -v brew >/dev/null 2>&1 || { pqb_err "Homebrew required on macOS: https://brew.sh"; exit 1; }
    NEED=()
    command -v cmake >/dev/null 2>&1 || NEED+=(cmake)
    command -v ninja >/dev/null 2>&1 || NEED+=(ninja)
    command -v git   >/dev/null 2>&1 || NEED+=(git)
    /opt/homebrew/opt/openssl@3.5/bin/openssl version >/dev/null 2>&1 || NEED+=(openssl@3.5)
    if [ "${#NEED[@]}" -gt 0 ]; then
      pqb_log "brew install ${NEED[*]}"
      brew install "${NEED[@]}"
    else
      pqb_log "all Homebrew deps already present"
    fi
    ;;
  linux)
    if command -v apt-get >/dev/null 2>&1; then
      pqb_install_build_deps
    else
      pqb_err "no apt-get on this system — install these with your package manager:"
      echo "  build-essential cmake ninja-build git python3 perl libssl-dev pkg-config util-linux linux-cpupower" >&2
      exit 1
    fi
    ;;
  *) pqb_err "unsupported platform '$PQB_OS'"; exit 1 ;;
esac

if [ "${RUST:-0}" = "1" ]; then
  if cargo --version >/dev/null 2>&1; then
    pqb_log "Rust already installed: $(cargo --version)"
  else
    pqb_log "installing Rust via the official rustup installer (https://rustup.rs)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    pqb_log "done — open a new shell or 'source \$HOME/.cargo/env' before make build"
  fi
else
  cargo --version >/dev/null 2>&1 || \
    pqb_warn "Rust not installed (2 of 4 measurement groups need it) — rerun as 'make deps RUST=1' to install via rustup"
fi
