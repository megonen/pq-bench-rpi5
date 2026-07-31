# =============================================================================
# Reproducible BUILD of the PQ benchmark C toolchain on Debian aarch64 (the
# same OS family as Raspberry Pi OS / Ubuntu on the RPi5).
#
# COVERAGE NOTE: C toolchain ONLY (liboqs / OpenSSL / oqs-provider). This image
# installs no Rust, so the RustCrypto (bench/rust) and rustls (bench/rust-tls)
# measurement groups are not built here, and the image has not been re-verified
# since those groups were added. The verified setup paths are the bare-metal
# ones in README.md / RUNNING-ON-YOUR-RPI5.md.
#
# This image is for BUILDING ONLY — it is NOT for running the benchmark.
#
#   docker build -t pq-bench-rpi5 .          # build + pin the toolchain
#
# Run the MEASUREMENT bare-metal on the host, never in the container. A
# container cannot reliably control the CPU governor, pin to an isolated core,
# or read the Pi's SoC thermal/throttle sensors (vcgencmd) — the three knobs the
# reference-grade gate depends on — so an in-container run could never be
# baseline-grade and would only add noise. Build here if you like; then:
#
#   ./run.sh                                 # on the host (see README)
# =============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git perl pkg-config \
      python3 python3-venv ca-certificates \
      libssl-dev cpufrequtils util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Build + pin the toolchain at image-build time so the image is self-contained.
# (Comment this out to keep the image thin and run setup.sh at container start.)
RUN ./setup/setup.sh all || (echo "setup failed — see log above" && exit 1)

# Optional: matplotlib PNG export in an isolated venv.
RUN python3 -m venv analyze/.venv \
    && analyze/.venv/bin/pip install --no-cache-dir -r analyze/requirements.txt

ENTRYPOINT ["/bin/bash", "-lc"]
# This image builds the toolchain; it does not run the benchmark. The default
# command just says so — run the measurement bare-metal on the host (see README).
CMD ["echo 'Toolchain built. Run the benchmark BARE-METAL on the host (./run.sh) — Docker is for reproducible builds only; a container cannot meet the baseline-grade gate.'"]
