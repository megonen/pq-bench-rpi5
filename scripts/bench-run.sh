#!/usr/bin/env bash
# =============================================================================
# make smoke / make run — platform-aware benchmark invocation.
#
# The run needs root for exactly ONE step: writing 'performance' into the
# sysfs CPU-governor files (see pqb_set_governor_performance). Everything
# else — cargo builds, the benchmarks, results — runs as the invoking user.
# Running the whole script under sudo (the old design) bit us three times:
# root-owned results/.work-* dirs, cargo-as-root (rustup cannot resolve a
# toolchain under root's HOME), and root-owned bench/*/target artifacts.
#
# So: on Linux, cache sudo credentials up front (sudo -v — one password
# prompt, before any measurement starts) and let the governor step escalate
# per-write with non-interactive `sudo -n`. If sudo is unavailable or
# declined, the run still completes and the governor demerit is recorded
# honestly (NOSUDO=1 skips the attempt entirely; same behavior).
#
# macOS: no governor to set — no escalation of any kind.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

if [ "$(uname -s)" = "Darwin" ] || [ "${NOSUDO:-0}" = "1" ] || [ "$(id -u)" -eq 0 ]; then
  exec ./run.sh "$@"
fi

if command -v sudo >/dev/null 2>&1 && sudo -v; then
  export PQB_GOV_SUDO=1
else
  echo "[bench-run] no sudo — running fully unprivileged; the governor demerit will be recorded" >&2
fi
exec ./run.sh "$@"
