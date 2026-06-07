# =============================================================================
# Reproducible build of the full PQ benchmark toolchain on Debian aarch64
# (the same OS family as Raspberry Pi OS / Ubuntu on the RPi5).
#
#   docker build -t pq-bench-rpi5 .
#   # build/pin liboqs + openssl + oqs-provider inside the image:
#   docker run --rm -v "$PWD/results:/app/results" pq-bench-rpi5 ./setup/setup.sh
#
# MEASUREMENT CAVEAT: a container cannot set the CPU governor or read the Pi's
# SoC sensors (vcgencmd) unless you grant it. For *baseline-grade* numbers run
# on the Pi natively, or grant the container what it needs, e.g.:
#   docker run --rm --privileged --cpuset-cpus=3 \
#     -v /usr/bin/vcgencmd:/usr/bin/vcgencmd -v /opt/vc:/opt/vc \
#     -v "$PWD/results:/app/results" pq-bench-rpi5 ./run.sh
# Otherwise the results JSON is correctly stamped is_baseline_grade=false.
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
CMD ["./run.sh --smoke"]
