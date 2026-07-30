#!/usr/bin/env bash
# =============================================================================
# make test-fedora — run check/build/test (and with SMOKE=1 a smoke run)
# inside a Fedora container, from a pristine copy of the CURRENT working tree.
#
# WHAT THIS COVERS: the class of bug that Mac + Pi testing structurally cannot
# catch — Red Hat packaging (openssl-devel), the lib64 install layout, dnf
# paths, and degradation on a machine with no governor control, no vcgencmd
# and no Pi-shaped thermal telemetry (the container has none of these, which
# is exactly the machine shape that has broken in the field).
#
# WHAT THIS DOES NOT COVER: measurements. Timings inside a container/VM are
# meaningless and nothing produced here is a benchmark result; runs are
# NOSUDO and land in the container's copy, never in this tree. On Apple
# Silicon the container is aarch64 Fedora (lib64 reproduces natively);
# ARCH=amd64 forces x86_64 under emulation for compile-and-run checks.
#
# Engine: podman or docker, autodetected. Image: fedora:42.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ENGINE=""
for e in podman docker; do
  command -v "$e" >/dev/null 2>&1 && "$e" info >/dev/null 2>&1 && { ENGINE="$e"; break; }
done
[ -n "$ENGINE" ] || { echo "no working container engine (podman or docker) — install one, e.g. 'brew install podman && podman machine init --now'" >&2; exit 1; }

PLATFORM_ARG=""
[ "${ARCH:-}" = "amd64" ] && PLATFORM_ARG="--platform=linux/amd64"

SMOKE_CMD=""
if [ "${SMOKE:-0}" = "1" ]; then
  SMOKE_CMD='echo "===== make smoke (NOSUDO, container) =====" && NOSUDO=1 make smoke'
fi

echo "[test-fedora] engine=$ENGINE image=fedora:42 ${ARCH:+arch=$ARCH }(source tree mounted read-only)"
# shellcheck disable=SC2086
"$ENGINE" run --rm $PLATFORM_ARG -v "$HERE":/src:ro fedora:42 bash -c '
  set -euo pipefail
  echo "== $(grep PRETTY /etc/os-release | cut -d= -f2 | tr -d \") $(uname -m) =="
  dnf install -y -q gcc gcc-c++ make cmake ninja-build git python3 perl \
      openssl openssl-devel pkgconf-pkg-config util-linux rsync
  # pristine copy: never build into the mounted host tree
  rsync -a --exclude vendor/ --exclude "bench/rust/target/" \
        --exclude "bench/rust-tls/target/" --exclude "results/.work-*" \
        --exclude "setup/versions.lock" \
        --exclude "bench/kem_sig/bench_pq" --exclude "bench/tls/bench_tls" \
        --exclude "bench/tls/pki/" --exclude "*.o" \
        /src/ /work/
  cd /work
  make check
  make build
  make test
  '"$SMOKE_CMD"'
  echo "[test-fedora] ALL GREEN"
'
