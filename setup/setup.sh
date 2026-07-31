#!/usr/bin/env bash
# =============================================================================
# setup.sh — build + pin the full PQ toolchain from scratch.
#
#   ./setup/setup.sh            # everything: deps, liboqs, openssl(if needed), oqs-provider
#   ./setup/setup.sh liboqs     # just liboqs
#   ./setup/setup.sh openssl    # just openssl (forced from source)
#   ./setup/setup.sh provider   # just oqs-provider
#   ./setup/setup.sh deps       # just OS packages
#
# Everything is installed under ./vendor/install (no system pollution). The exact
# resolved git commits + the optimization flags actually used are written to
# setup/versions.lock, which run.sh stamps into every results JSON.
#
# Identical flags for every candidate: -O3 -mcpu=cortex-a76 on the RPi5. On a
# non-A76 host (the macOS smoke box) we fall back to -O3 and RECORD that, so
# smoke-test numbers can never masquerade as the RPi5 baseline.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=setup/lib_platform.sh
source "$HERE/lib_platform.sh"
# shellcheck source=setup/versions.env
source "$HERE/versions.env"

pqb_detect_platform
# set -e deaths must never be silent (see run.sh)
set -E  # errtrace: without it the ERR trap does not fire inside functions
trap 'pqb_err "setup.sh aborted at line $LINENO while running: $BASH_COMMAND"' ERR

VENDOR="$ROOT/vendor"
SRC="$VENDOR/src"
PREFIX="$VENDOR/install"
mkdir -p "$SRC" "$PREFIX"

JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
LOGDIR="$VENDOR/logs"
mkdir -p "$LOGDIR"

# run_logged <name> <cmd...> — build steps must never fail silently. The old
# `cmake --build ... >/dev/null` pattern discarded compiler errors entirely
# when the generator was Ninja (unlike make, ninja merges the compiler's
# stderr into its own STDOUT — so >/dev/null swallowed the actual error and
# the run died with nothing but an exit code). Full output goes to a log
# file; on failure the tail is replayed so the real error is on screen.
run_logged() {
  local name="$1"; shift
  local log="$LOGDIR/$name.log" rc=0
  "$@" >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    pqb_err "step '$name' FAILED (exit $rc): $*"
    pqb_err "last 30 lines of $log:"
    tail -30 "$log" >&2
    return $rc
  fi
}

# ---- decide the real optimization flags for THIS host ----------------------
# Detection lives in lib_platform.sh (pqb_choose_cflags): cortex-a76 on Linux
# aarch64, apple-mN via -mcpu=native on Apple-silicon macOS, fallback elsewhere.
choose_cflags() {
  pqb_choose_cflags
}

cc_version_string() {
  local cc="${CC:-cc}"
  "$cc" --version 2>/dev/null | head -1
}

git_pin() { # repo ref destdir
  local repo="$1" ref="$2" dest="$3"
  if [ -d "$dest/.git" ]; then
    pqb_log "updating $(basename "$dest") -> $ref"
    git -C "$dest" fetch -q --depth 1 origin "$ref" || git -C "$dest" fetch -q --tags origin
  else
    pqb_log "cloning $(basename "$dest") @ $ref"
    git clone -q --depth 1 --branch "$ref" "$repo" "$dest" 2>/dev/null \
      || git clone -q "$repo" "$dest"
  fi
  git -C "$dest" checkout -q "$ref" 2>/dev/null || true
  git -C "$dest" rev-parse HEAD
}

# ---------------------------------------------------------------------------
build_liboqs() {
  choose_cflags
  # liboqs links libcrypto for AES/SHA-2 (OQS_USE_{AES,SHA2}_OPENSSL default
  # ON), so it MUST build against the same pinned OpenSSL as everything else —
  # otherwise bench_pq/bench_tls load two libcrypto versions in one process
  # and the AES/SHA-2-dependent rows silently measure a different OpenSSL.
  [ -n "${OPENSSL_PREFIX:-}" ] || locate_or_build_openssl
  local dest="$SRC/liboqs" commit
  commit="$(git_pin "$LIBOQS_REPO" "$LIBOQS_REF" "$dest")"
  pqb_log "building liboqs ($LIBOQS_REF @ ${commit:0:12}) flags: $BENCH_CFLAGS openssl: $OPENSSL_PREFIX"

  # OQS_DIST_BUILD=OFF -> native build for the fixed target (no runtime CPU
  # dispatch), so -mcpu=cortex-a76 fully drives codegen. The AArch64-optimized
  # ML-KEM (mlkem-native) and AArch64 asm backends are enabled by default on
  # aarch64 when DIST_BUILD is OFF (compile-time CPU features); verified post-build.
  local GEN=(); command -v ninja >/dev/null 2>&1 && GEN=(-G Ninja)
  # CMAKE_INSTALL_LIBDIR=lib pins ONE install layout on every platform:
  # GNUInstallDirs defaults to lib64 on Red Hat family, which broke every
  # hand-written path downstream (-L, rpath, the guards) while cmake's own
  # find_package kept working — the root cause of the Fedora failure chain.
  # Nothing outside this repo consumes vendor/install, so forcing lib is safe.
  run_logged liboqs-configure cmake -S "$dest" -B "$dest/build" ${GEN[@]+"${GEN[@]}"} \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_BUILD_ONLY_LIB=OFF \
    -DBUILD_SHARED_LIBS=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DCMAKE_INSTALL_RPATH="$PREFIX/lib" \
    -DCMAKE_C_FLAGS="$BENCH_CFLAGS"
  run_logged liboqs-build cmake --build "$dest/build" --parallel "$JOBS"
  run_logged liboqs-install cmake --install "$dest/build"

  # Prove the optimized backend: capture the aarch64/native defines from the
  # generated build config so versions.lock can show what was actually compiled.
  local cfg="$dest/build/include/oqs/oqsconfig.h"
  LIBOQS_OPT_DEFINES="(oqsconfig.h not found)"
  if [ -r "$cfg" ]; then
    # strip embedded double-quotes so the value stays valid in versions.lock
    LIBOQS_OPT_DEFINES="$(grep -Ei 'AARCH64|ARM|_ASM|MLKEM_NATIVE|OPT_TARGET|CPU_EXT' "$cfg" \
      | grep -i 'define' | sed 's/^#define //' | tr -d '"' | tr '\n' ';' || true)"
  fi
  LIBOQS_COMMIT="$commit"
}

# ---------------------------------------------------------------------------
locate_or_build_openssl() {
  # OpenSSL is PINNED to the 3.5.x LTS line on every platform (macOS: keg-only
  # Homebrew openssl@3.5; Debian 13 ships 3.5.x as the system openssl), so
  # Mac-vs-Pi TLS numbers never compare different OpenSSL minor lines. Pass 1
  # accepts only 3.5.x; pass 2 falls back to any >= 3.5 with a loud warning and
  # records the deviation via OPENSSL_COMMIT (stamped into every results JSON).
  local want_major=3 want_minor=5
  if [ "${1:-}" != "force" ] && [ "${BUILD_OPENSSL:-0}" != 1 ]; then
    # Reuse an already-vendored source build first: the phases run as separate
    # processes, and the candidate walk below only looks at keg/system paths,
    # so without this every phase would source-build OpenSSL again from
    # scratch. Probing by EXECUTION is deliberate — it proves the binary
    # resolves its own libssl/libcrypto (the rpath baked in below); an
    # rpath-less build from before that fix fails this probe and is rebuilt.
    # OPENSSL_COMMIT stays unset here: write_lock seeds it from the existing
    # lock, which has the real commit.
    if [ -x "$PREFIX/bin/openssl" ]; then
      local vv
      vv="$("$PREFIX/bin/openssl" version 2>/dev/null | awk '{print $2}')"
      case "$vv" in
        "$want_major.$want_minor".*)
          OPENSSL_BIN="$PREFIX/bin/openssl"
          OPENSSL_PREFIX="$PREFIX"
          pqb_log "reusing vendored OpenSSL $vv at $PREFIX"
          return 0 ;;
      esac
    fi
    local pass cand
    for pass in pinned fallback; do
      for cand in /opt/homebrew/opt/openssl@3.5/bin/openssl \
                  "$(command -v openssl || true)" \
                  /opt/homebrew/opt/openssl@3/bin/openssl /usr/bin/openssl; do
        [ -x "$cand" ] || continue
        local v; v="$("$cand" version 2>/dev/null | awk '{print $2}')"
        # NB: assign on separate lines. A single `local a=.. b=.. c="${b..}"` makes
        # bash 5.2 declare all names (unset) *before* expanding any RHS, so the
        # reference to `rest` here trips `set -u` (unbound variable) on the Pi.
        local maj rest min
        maj="${v%%.*}"; rest="${v#*.}"; min="${rest%%.*}"
        if [ "$pass" = pinned ]; then
          [ "${maj:-0}" = "$want_major" ] && [ "${min:-0}" = "$want_minor" ] || continue
        else
          [ "${maj:-0}" -gt "$want_major" ] 2>/dev/null || \
            { [ "${maj:-0}" -eq "$want_major" ] && [ "${min:-0}" -ge "$want_minor" ]; } 2>/dev/null \
            || continue
          pqb_warn "no OpenSSL on the pinned 3.5.x line found; using $v at $cand — cross-machine TLS comparisons must check toolchain.openssl"
        fi
        OPENSSL_BIN="$cand"
        OPENSSL_PREFIX="$(dirname "$(dirname "$cand")")"
        OPENSSL_COMMIT="system:$v"
        pqb_log "using existing OpenSSL $v at $cand"
        return 0
      done
    done
  fi
  pqb_log "building OpenSSL $OPENSSL_REF from source"
  local dest="$SRC/openssl" commit
  commit="$(git_pin "$OPENSSL_REPO" "$OPENSSL_REF" "$dest")"
  # --libdir=lib: OpenSSL's own Configure defaults to lib64 on Red Hat-family
  # x86_64 — same one-layout pin as CMAKE_INSTALL_LIBDIR=lib for the cmake
  # projects (downstream -L/rpath/guards all assume vendor/install/lib).
  # -Wl,-rpath: without it the installed bin/openssl resolves libssl/libcrypto
  # from the SYSTEM path (on Fedora that's the older 3.2.x — symbol-version
  # errors on every invocation), because the source build only happens on
  # hosts whose system OpenSSL is older than the pin.
  ( cd "$dest" \
      && run_logged openssl-configure ./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" \
           --libdir=lib shared "-Wl,-rpath,$PREFIX/lib" \
      && run_logged openssl-build make -j"$JOBS" \
      && run_logged openssl-install make install_sw \
      && run_logged openssl-install-ssldirs make install_ssldirs )
      # install_ssldirs: install_sw alone ships no openssl.cnf; every `openssl
      # req` (PKI generation) then fails with "Can't open .../ssl/openssl.cnf"
  OPENSSL_BIN="$PREFIX/bin/openssl"
  OPENSSL_PREFIX="$PREFIX"
  OPENSSL_COMMIT="$commit"
}

# ---------------------------------------------------------------------------
build_oqs_provider() {
  [ -n "${OPENSSL_PREFIX:-}" ] || locate_or_build_openssl
  local dest="$SRC/oqs-provider" commit
  commit="$(git_pin "$OQSPROVIDER_REPO" "$OQSPROVIDER_REF" "$dest")"
  pqb_log "building oqs-provider ($OQSPROVIDER_REF @ ${commit:0:12})"
  local GEN=(); command -v ninja >/dev/null 2>&1 && GEN=(-G Ninja)
  run_logged provider-configure cmake -S "$dest" -B "$dest/build" ${GEN[@]+"${GEN[@]}"} \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -Dliboqs_DIR="$PREFIX/lib/cmake/liboqs" \
    -DCMAKE_INSTALL_RPATH="$PREFIX/lib" \
    -DCMAKE_C_FLAGS="${BENCH_CFLAGS:-$TARGET_CFLAGS_FALLBACK}"
  run_logged provider-build cmake --build "$dest/build" --parallel "$JOBS"
  run_logged provider-install cmake --install "$dest/build" || true
  # Provider .so lands under .../lib/ossl-modules or .../oqsprovider
  OQSPROVIDER_MODULE="$(find "$PREFIX" "$dest/build" -name 'oqsprovider.*' \( -name '*.so' -o -name '*.dylib' \) 2>/dev/null | head -1)"
  OQSPROVIDER_COMMIT="$commit"
}

# ---------------------------------------------------------------------------
write_lock() {
  choose_cflags 2>/dev/null || true
  local lock="$HERE/versions.lock"
  # Partial runs (e.g. `setup.sh provider`) must not erase the provenance of
  # components built earlier: seed any variable NOT set by this invocation from
  # the existing lock, so the lock always describes the full installed state.
  if [ -f "$lock" ]; then
    local k v
    while IFS='=' read -r k v; do
      case "$k" in ''|\#*) continue ;; esac
      v="${v%\"}"; v="${v#\"}"
      case "$k" in
        LIBOQS_COMMIT|LIBOQS_OPT_DEFINES|OPENSSL_BIN|OPENSSL_PREFIX|OPENSSL_COMMIT|OQSPROVIDER_COMMIT|OQSPROVIDER_MODULE)
          eval ": \"\${$k:=\$v}\"" ;;
      esac
    done < "$lock"
  fi
  {
    echo "# Auto-generated by setup.sh — exact toolchain provenance. Stamped into results JSON."
    echo "PQB_BUILD_HOST_OS=$PQB_OS"
    echo "PQB_BUILD_HOST_ARCH=$PQB_ARCH"
    echo "PQB_IS_RPI=$PQB_IS_RPI"
    echo "PQB_RPI_MODEL=\"${PQB_RPI_MODEL}\""
    echo "BENCH_CFLAGS=\"${BENCH_CFLAGS:-unknown}\""
    echo "CFLAGS_TARGET=\"${CFLAGS_TARGET:-unknown}\""
    echo "CC_VERSION=\"$(cc_version_string)\""
    echo "LIBOQS_REF=\"$LIBOQS_REF\""
    echo "LIBOQS_COMMIT=\"${LIBOQS_COMMIT:-not-built}\""
    echo "LIBOQS_OPT_DEFINES=\"${LIBOQS_OPT_DEFINES:-}\""
    echo "OPENSSL_BIN=\"${OPENSSL_BIN:-}\""
    echo "OPENSSL_PREFIX=\"${OPENSSL_PREFIX:-}\""
    echo "OPENSSL_COMMIT=\"${OPENSSL_COMMIT:-not-built}\""
    echo "OQSPROVIDER_REF=\"$OQSPROVIDER_REF\""
    echo "OQSPROVIDER_COMMIT=\"${OQSPROVIDER_COMMIT:-not-built}\""
    echo "OQSPROVIDER_MODULE=\"${OQSPROVIDER_MODULE:-}\""
    echo "PREFIX=\"$PREFIX\""
  } > "$lock"
  pqb_log "wrote $lock"
  cat "$lock" >&2
}

# ---- dispatch --------------------------------------------------------------
main() {
  local what="${1:-all}"
  case "$what" in
    deps)     pqb_install_build_deps ;;
    liboqs)   build_liboqs; write_lock ;;
    openssl)  locate_or_build_openssl force; write_lock ;;
    provider) build_oqs_provider; write_lock ;;
    all)
      pqb_install_build_deps
      build_liboqs
      locate_or_build_openssl
      build_oqs_provider
      write_lock
      pqb_log "setup complete. Next: ./run.sh --smoke"
      ;;
    *) pqb_err "unknown target: $what (deps|liboqs|openssl|provider|all)"; exit 2 ;;
  esac
}
main "$@"
