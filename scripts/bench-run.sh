#!/usr/bin/env bash
# =============================================================================
# make smoke / make run — platform-aware benchmark invocation.
#
# Linux: baseline-grade runs need root for the governor, but rustup installs
# per-user, so plain `sudo ./run.sh` silently loses both Rust groups (rustup
# cannot resolve a toolchain under root's HOME — found the hard way on a Pi).
# The full, correct form is baked in here so nobody has to know it:
#   sudo env "PATH=$PATH" "RUSTUP_HOME=$HOME/.rustup" "CARGO_HOME=$HOME/.cargo" ./run.sh
# NOSUDO=1 skips sudo (run completes; governor demerit is recorded honestly).
#
# macOS: no governor to set — sudo is never needed.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

if [ "$(uname -s)" = "Darwin" ] || [ "${NOSUDO:-0}" = "1" ] || [ "$(id -u)" -eq 0 ]; then
  exec ./run.sh "$@"
fi
exec sudo env "PATH=$PATH" "RUSTUP_HOME=$HOME/.rustup" "CARGO_HOME=$HOME/.cargo" ./run.sh "$@"
