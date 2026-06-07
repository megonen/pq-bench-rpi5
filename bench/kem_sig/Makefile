# Build the primitive KEM/sig harness against the pinned liboqs + system OpenSSL.
#
# Paths/flags default to the vendored toolchain but are overridable so run.sh can
# pass the exact values from setup/versions.lock (single source of truth):
#   make LIBOQS_PREFIX=... OPENSSL_PREFIX=... BENCH_CFLAGS="-O3 -mcpu=cortex-a76"

ROOT          := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
LIBOQS_PREFIX ?= $(ROOT)/vendor/install
# OpenSSL: prefer Homebrew openssl@3 on macOS, else system.
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || echo /usr)
BENCH_CFLAGS  ?= -O3

CC     ?= cc
CFLAGS := $(BENCH_CFLAGS) -std=c11 -Wall -Wextra \
          -I$(LIBOQS_PREFIX)/include -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(LIBOQS_PREFIX)/lib -L$(OPENSSL_PREFIX)/lib \
           -Wl,-rpath,$(LIBOQS_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
LDLIBS  := -loqs -lcrypto -lm

bench_pq: bench_pq.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f bench_pq

.PHONY: clean
