# shellcheck shell=bash
# =============================================================================
# lib_platform.sh — portable platform abstraction
#
# Sourced by setup/setup.sh and run.sh. Every operation that differs between the
# RPi5 (Debian/Ubuntu aarch64) measurement target and the macOS/Apple-Silicon
# dev box is funneled through one of these functions, so the *identical* codebase
# runs unchanged on both. Where a capability does not exist on a platform
# (governor control, core pinning, on-die thermal sensors), the function degrades
# gracefully and the caller records that it was unavailable — it never silently
# pretends the action happened.
# =============================================================================

# ---- platform detection ----------------------------------------------------
# Sets: PQB_OS (macos|linux), PQB_ARCH, PQB_IS_RPI (1|0), PQB_RPI_MODEL
pqb_detect_platform() {
  PQB_ARCH="$(uname -m)"
  case "$(uname -s)" in
    Darwin) PQB_OS="macos" ;;
    Linux)  PQB_OS="linux" ;;
    *)      PQB_OS="unknown" ;;
  esac

  PQB_IS_RPI=0
  PQB_RPI_MODEL=""
  if [ "$PQB_OS" = "linux" ] && [ -r /proc/device-tree/model ]; then
    # /proc/device-tree/model is NUL-terminated
    PQB_RPI_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
    case "$PQB_RPI_MODEL" in
      *"Raspberry Pi"*) PQB_IS_RPI=1 ;;
    esac
  fi
  export PQB_OS PQB_ARCH PQB_IS_RPI PQB_RPI_MODEL
}

# ---- Linux distro family (for package-name hints and deps installs) --------
# echoes: debian | fedora | arch | suse | unknown
# PQB_TEST_OS_RELEASE overrides the os-release path (test hook, used to
# exercise the per-distro output of make check on other platforms).
pqb_linux_family() {
  local osr="${PQB_TEST_OS_RELEASE:-/etc/os-release}" id="" like=""
  if [ -r "$osr" ]; then
    id="$(. "$osr" 2>/dev/null; echo "${ID:-}")"
    like="$(. "$osr" 2>/dev/null; echo "${ID_LIKE:-}")"
  fi
  case " $id $like " in
    *debian*|*ubuntu*|*raspbian*)            echo debian ;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*) echo fedora ;;
    *arch*)                                  echo arch ;;
    *suse*)                                  echo suse ;;
    *)                                       echo unknown ;;
  esac
}

# ---- optimization-target resolution ----------------------------------------
# Resolve THIS host's tuned build flags (the credibility anchor: identical,
# host-tuned flags for every candidate; the resolved values go into
# versions.lock and every results JSON):
#   Linux aarch64 (the RPi5 target):  -O3 -mcpu=cortex-a76 / "cortex-a76"
#   Apple-silicon macOS (uname -m is  -O3 -mcpu=native     / "apple-mN"
#     "arm64", NOT "aarch64" — the      (label from the CPU brand string)
#     old check missed Macs entirely
#     and silently fell back to -O3)
#   anything else:                    $TARGET_CFLAGS_FALLBACK / "generic-fallback"
# Each candidate flag set is probe-compiled first; a rejected flag falls back
# rather than failing the build. Rust harnesses mirror this via RUSTFLAGS in
# run.sh (cortex-a76 -> target-cpu=cortex-a76, apple-m* -> target-cpu=native).
pqb_choose_cflags() {  # sets + exports BENCH_CFLAGS, CFLAGS_TARGET
  local cc="${CC:-cc}" tmp probe
  tmp="$(mktemp -d)" && probe="$tmp/probe.c" && echo 'int main(void){return 0;}' > "$probe"
  BENCH_CFLAGS="${TARGET_CFLAGS_FALLBACK:--O3}"
  CFLAGS_TARGET="generic-fallback"
  # shellcheck disable=SC2086
  if [ "$PQB_OS" = "linux" ] && [ "$PQB_ARCH" = "aarch64" ] && \
     $cc ${TARGET_CFLAGS_RPI5:--O3 -mcpu=cortex-a76} "$probe" -o "$probe.out" 2>/dev/null; then
    BENCH_CFLAGS="${TARGET_CFLAGS_RPI5:--O3 -mcpu=cortex-a76}"
    CFLAGS_TARGET="cortex-a76"
  elif [ "$PQB_OS" = "macos" ] && [ "$PQB_ARCH" = "arm64" ] && \
       $cc -O3 -mcpu=native "$probe" -o "$probe.out" 2>/dev/null; then
    BENCH_CFLAGS="-O3 -mcpu=native"
    local brand
    brand="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'apple silicon')"
    CFLAGS_TARGET="$(printf '%s' "$brand" | tr '[:upper:] ' '[:lower:]-')"
  fi
  rm -rf "$tmp"
  export BENCH_CFLAGS CFLAGS_TARGET
}

# ---- friendly logging ------------------------------------------------------
pqb_log()  { printf '\033[1;34m[pqb]\033[0m %s\n' "$*" >&2; }
pqb_warn() { printf '\033[1;33m[pqb WARN]\033[0m %s\n' "$*" >&2; }
pqb_err()  { printf '\033[1;31m[pqb ERR]\033[0m %s\n' "$*" >&2; }

# ---- hostname resolution ---------------------------------------------------
# A "good" host id is non-empty, not localhost, and not an avahi/macOS
# auto-assigned "unknown<hexMAC>" placeholder (which is what shows up when no
# real hostname is set — that produced the ugly results filename before).
_pqb_good_host() {
  local h="$1"
  [ -n "$h" ] || return 1
  case "$h" in
    localhost|localhost.*) return 1 ;;
  esac
  printf '%s' "$h" | grep -Eq '^[Uu]nknown[0-9a-fA-F]{6,}$' && return 1
  return 0
}

# Resolve a readable, stable host identifier, falling through:
#   $HOSTNAME -> `hostname` -> hostnamectl --static (Linux) /
#   scutil --get LocalHostName (macOS) -> short machine id (last resort).
# Domain suffixes (.home/.local/...) are stripped. On the RPi5 this yields the
# actual pi hostname; on this Mac it falls through to LocalHostName.
pqb_resolve_hostname() {
  local cands=() c h
  cands+=("${HOSTNAME:-}")
  cands+=("$(hostname 2>/dev/null || true)")
  if [ "${PQB_OS:-}" = "linux" ]; then
    cands+=("$(hostnamectl --static 2>/dev/null || true)")
  elif [ "${PQB_OS:-}" = "macos" ]; then
    cands+=("$(scutil --get LocalHostName 2>/dev/null || true)")
  fi
  for c in "${cands[@]}"; do
    h="${c%%.*}"                         # strip domain suffix
    if _pqb_good_host "$h"; then echo "$h"; return 0; fi
  done
  # last resort: a short, stable machine id so files never collide as "unknown"
  local mid=""
  if [ -r /etc/machine-id ]; then
    mid="$(cut -c1-12 /etc/machine-id 2>/dev/null)"
  elif [ "${PQB_OS:-}" = "macos" ]; then
    mid="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
           | awk -F'"' '/IOPlatformUUID/{print $4}' | tr -d '-' | cut -c1-12)"
  fi
  echo "host-${mid:-unknown}"
}

# ---- CPU governor ----------------------------------------------------------
# Returns 0 if it set 'performance', 1 if unavailable. Prints the governor it
# left the system in on stdout.
#
# This is the ONLY privileged operation in the whole run (the sysfs governor
# files are root-writable only), so it is the only step allowed to escalate.
# The measurement itself runs as the invoking user — running everything under
# sudo bit us three times (root-owned results/.work-* dirs, cargo-as-root,
# root-owned bench/*/target artifacts). bench-run.sh caches credentials up
# front (sudo -v) and sets PQB_GOV_SUDO=1; writes then use non-interactive
# `sudo -n`, so a run can never stall on a mid-run password prompt.
pqb_set_governor_performance() {
  if [ "$PQB_OS" = "linux" ] && [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    local ok=1 g
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      if [ -w "$g" ]; then
        echo performance > "$g" 2>/dev/null || ok=0
      elif [ "${PQB_GOV_SUDO:-0}" = 1 ] && command -v sudo >/dev/null 2>&1; then
        echo performance | sudo -n tee "$g" >/dev/null 2>&1 || ok=0
      else
        ok=0
      fi
    done
    if [ "$ok" = 1 ]; then
      cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null
      return 0
    fi
    # cpupower fallback, same single-step escalation rules
    if command -v cpupower >/dev/null 2>&1; then
      if cpupower frequency-set -g performance >/dev/null 2>&1 \
         || { [ "${PQB_GOV_SUDO:-0}" = 1 ] && command -v sudo >/dev/null 2>&1 \
              && sudo -n cpupower frequency-set -g performance >/dev/null 2>&1; }; then
        echo performance; return 0
      fi
    fi
    pqb_warn "could not set governor to performance (use 'make run' so this one step can escalate, or accept the non-baseline demerit)"
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown"
    return 1
  fi
  # macOS / other: no userspace governor control.
  echo "unavailable"
  return 1
}

pqb_get_governor() {
  if [ "$PQB_OS" = "linux" ] && [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
  else
    echo "unavailable"
  fi
}

# ---- core pinning ----------------------------------------------------------
# pqb_taskset_prefix <core> -> echoes a command prefix to pin to that core, or
# empty string if pinning is unavailable (caller warns).
pqb_taskset_prefix() {
  local core="$1"
  if command -v taskset >/dev/null 2>&1; then
    echo "taskset -c $core"
  elif command -v numactl >/dev/null 2>&1; then
    echo "numactl --physcpubind=$core"
  else
    echo ""   # no pinning available (e.g. macOS)
  fi
}

# ---- thermal / clock sampling ----------------------------------------------
# pqb_sample_thermal -> one CSV line: epoch_s,arm_clock_hz,temp_c,throttled_hex
# Fields that cannot be read on a platform are emitted as empty (no fake zeros).
pqb_sample_thermal() {
  local ts clk temp thr
  ts="$(date +%s)"
  clk=""; temp=""; thr=""

  if command -v vcgencmd >/dev/null 2>&1; then
    # Raspberry Pi: authoritative SoC sensors.
    clk="$(vcgencmd measure_clock arm 2>/dev/null | sed -n 's/.*=//p')"
    temp="$(vcgencmd measure_temp 2>/dev/null | sed -n "s/temp=\([0-9.]*\).*/\1/p")"
    thr="$(vcgencmd get_throttled 2>/dev/null | sed -n 's/.*=//p')"
  elif [ "$PQB_OS" = "linux" ]; then
    # Generic Linux fallback (cpufreq + thermal_zone).
    local f
    f=/sys/devices/system/cpu/cpu${PQB_BENCH_CORE:-0}/cpufreq/scaling_cur_freq
    [ -r "$f" ] && clk="$(( $(cat "$f") * 1000 ))"   # kHz -> Hz
    if [ -r /sys/class/thermal/thermal_zone0/temp ]; then
      local milli; milli="$(cat /sys/class/thermal/thermal_zone0/temp)"
      temp="$(awk -v m="$milli" 'BEGIN{printf "%.1f", m/1000}')"
    fi
  fi
  # macOS: live per-core freq/temp require sudo powermetrics; we intentionally
  # leave them empty rather than emit misleading values. (Smoke test only.)

  printf '%s,%s,%s,%s\n' "$ts" "$clk" "$temp" "$thr"
}

# pqb_throttled_active <throttled_hex> -> 0 if thermal throttling currently/has
# occurred, 1 otherwise. RPi get_throttled bit 0 = under-voltage now,
# bit 1 = arm freq capped now, bit 2 = currently throttled,
# bit 3 = soft temp limit active (and bits 16-19 = "has occurred" latches).
pqb_throttled_active() {
  local hex="${1#0x}"
  [ -z "$hex" ] && return 1
  local val=$(( 16#$hex ))
  # bit2 (throttling now) or bit18 (throttling has occurred)
  if [ $(( val & 0x4 )) -ne 0 ] || [ $(( val & 0x40000 )) -ne 0 ]; then
    return 0
  fi
  return 1
}

# ---- CPU feature / crypto-extension detection ------------------------------
# Echoes a JSON object describing NEON + SHA3/SHA512 acceleration. Consumed
# verbatim by env metadata so results record whether Keccak accel is in use.
pqb_cpu_features_json() {
  local neon=false sha2=false sha3=false sha512=false aes=false pmull=false src="unknown"
  if [ "$PQB_OS" = "linux" ] && [ -r /proc/cpuinfo ]; then
    # ARM /proc/cpuinfo has a 'Features' line; x86 has 'flags' instead. The
    # grep MUST NOT propagate failure: under run.sh's `set -e -o pipefail` a
    # missing 'Features' line (any x86 box) previously killed the whole run
    # with no diagnostic, right after the thermal sampler started.
    local feats
    feats="$(grep -m1 -i '^Features' /proc/cpuinfo 2>/dev/null | tr 'A-Z' 'a-z' || true)"
    if [ -n "$feats" ]; then
      src="/proc/cpuinfo (Features)"
      case "$feats" in *" asimd"*|*"neon"*) neon=true;; esac
      case "$feats" in *" sha2"*) sha2=true;; esac
      case "$feats" in *" sha3"*) sha3=true;; esac
      case "$feats" in *" sha512"*) sha512=true;; esac
      case "$feats" in *" aes"*) aes=true;; esac
      case "$feats" in *" pmull"*) pmull=true;; esac
    else
      # x86: map the 1:1 equivalents from the 'flags' line (aes -> AES-NI,
      # sha_ni -> SHA-2 instructions, pclmulqdq -> carry-less multiply).
      # neon/sha3/sha512 stay false: they are ARM-specific extensions.
      src="/proc/cpuinfo (flags, x86)"
      local flags
      flags="$(grep -m1 -i '^flags' /proc/cpuinfo 2>/dev/null | tr 'A-Z' 'a-z' || true)"
      case "$flags" in *" aes"*) aes=true;; esac
      case "$flags" in *" sha_ni"*) sha2=true;; esac
      case "$flags" in *" pclmulqdq"*) pmull=true;; esac
    fi
  elif [ "$PQB_OS" = "macos" ]; then
    src="sysctl"
    neon=true   # all Apple Silicon has NEON/ASIMD
    [ "$(sysctl -n hw.optional.arm.FEAT_SHA256 2>/dev/null)" = 1 ] && sha2=true
    [ "$(sysctl -n hw.optional.arm.FEAT_SHA3   2>/dev/null)" = 1 ] && sha3=true
    [ "$(sysctl -n hw.optional.arm.FEAT_SHA512 2>/dev/null)" = 1 ] && sha512=true
    [ "$(sysctl -n hw.optional.arm.FEAT_AES    2>/dev/null)" = 1 ] && aes=true
    [ "$(sysctl -n hw.optional.arm.FEAT_PMULL  2>/dev/null)" = 1 ] && pmull=true
  fi
  printf '{"source":"%s","neon":%s,"sha2":%s,"sha3":%s,"sha512":%s,"aes":%s,"pmull":%s}' \
    "$src" "$neon" "$sha2" "$sha3" "$sha512" "$aes" "$pmull"
}

# ---- package installation --------------------------------------------------
# pqb_install_build_deps -> installs compiler/cmake/openssl headers per platform.
pqb_install_build_deps() {
  if [ "$PQB_OS" = "macos" ]; then
    command -v brew >/dev/null 2>&1 || { pqb_err "Homebrew required on macOS: https://brew.sh"; return 1; }
    pqb_log "installing build deps via Homebrew"
    brew install cmake ninja openssl@3.5 git python3 >/dev/null || true
  elif [ "$PQB_OS" = "linux" ]; then
    local SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    case "$(pqb_linux_family)" in
      debian)
        pqb_log "installing build deps via apt (Debian family)"
        $SUDO apt-get update -qq
        # linux-cpupower provides the `cpupower` binary used by
        # pqb_set_governor_performance. (Older releases shipped cpufrequtils,
        # dropped in Debian 13/trixie — cpupower is the replacement.)
        # libssl-dev: the openssl BINARY is not enough — liboqs/oqs-provider
        # need headers + a linkable libcrypto (the Fedora lesson, same idea).
        $SUDO apt-get install -y -qq \
          build-essential cmake ninja-build git python3 perl \
          libssl-dev pkg-config astyle doxygen \
          linux-cpupower util-linux >/dev/null
        ;;
      fedora)
        pqb_log "installing build deps via dnf (Fedora/RHEL family)"
        # openssl-devel is the critical one: Fedora ships the openssl binary
        # separately from the development files, and the liboqs cmake build
        # fails with 'Could NOT find OpenSSL (missing OPENSSL_CRYPTO_LIBRARY
        # OPENSSL_INCLUDE_DIR)' without it.
        $SUDO dnf install -y \
          gcc gcc-c++ make cmake ninja-build git python3 perl \
          openssl openssl-devel pkgconf-pkg-config \
          kernel-tools util-linux
        ;;
      arch)
        pqb_warn "Arch detected (unverified platform) — install manually:"
        echo "  sudo pacman -S --needed base-devel cmake ninja git python openssl perl" >&2
        return 1
        ;;
      suse)
        pqb_warn "openSUSE detected (unverified platform) — install manually:"
        echo "  sudo zypper install gcc gcc-c++ make cmake ninja git python3 perl libopenssl-devel" >&2
        return 1
        ;;
      *)
        pqb_warn "unknown Linux family; install with your package manager:"
        echo "  C compiler, make, cmake, ninja, git, python3, perl, OpenSSL development files (headers + libcrypto)" >&2
        return 1
        ;;
    esac
  fi
}
