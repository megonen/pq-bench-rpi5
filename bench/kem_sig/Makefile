# Build the primitive KEM/sig harness against the pinned liboqs + system OpenSSL.
#
# Paths/flags default to the vendored toolchain but are overridable so run.sh can
# pass the exact values from setup/versions.lock (single source of truth):
#   make LIBOQS_PREFIX=... OPENSSL_PREFIX=... BENCH_CFLAGS="-O3 -mcpu=cortex-a76"

ROOT          := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
LIBOQS_PREFIX ?= $(ROOT)/vendor/install
# OpenSSL: prefer the pinned keg-only Homebrew openssl@3.5 on macOS, else system.
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3.5 2>/dev/null || echo /usr)
BENCH_CFLAGS  ?= -O3

CC     ?= cc
CFLAGS := $(BENCH_CFLAGS) -std=c11 -Wall -Wextra \
          -I$(LIBOQS_PREFIX)/include -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(LIBOQS_PREFIX)/lib -L$(OPENSSL_PREFIX)/lib \
           -Wl,-rpath,$(LIBOQS_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
LDLIBS  := -loqs -lcrypto -lm

# NB: the guard target is declared before bench_pq, so pin the default goal
# explicitly — otherwise a bare `make` would run only the guard and "succeed"
# without producing a binary.
.DEFAULT_GOAL := bench_pq

# HARD GUARD: refuse to build against anything but the vendored liboqs. With
# vendor/install empty, -L would silently fall through to a system liboqs
# (e.g. a distro liboqs-devel) and every measurement would run against an
# unpinned library — the version pin is the whole basis of comparability, and
# the pinned oqs-provider expects exactly the pinned liboqs' headers.
liboqs-guard:
	@if ! test -f "$(LIBOQS_PREFIX)/include/oqs/oqs.h" || ! ls "$(LIBOQS_PREFIX)"/lib/liboqs.* >/dev/null 2>&1; then \
	  echo "ERROR: pinned vendored liboqs not found. Looked for BOTH of:"; \
	  echo "  $(LIBOQS_PREFIX)/include/oqs/oqs.h"; \
	  echo "  $(LIBOQS_PREFIX)/lib/liboqs.*"; \
	  echo "Inspect what is actually there with: ls $(LIBOQS_PREFIX)"; \
	  echo "- Nothing there: the toolchain build did not run or failed -- check the"; \
	  echo "  output of 'make build' / ./setup/setup.sh for the original error."; \
	  echo "- A lib64/ directory: the toolchain was built before the install layout"; \
	  echo "  was pinned (-DCMAKE_INSTALL_LIBDIR=lib) -- 'make distclean && make build'."; \
	  echo "Either way, do NOT install a distro liboqs to work around this: linking a"; \
	  echo "system liboqs is refused because unpinned versions are not comparable with"; \
	  echo "the published baselines."; \
	  exit 1; \
	fi

bench_pq: bench_pq.c | liboqs-guard
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f bench_pq

.PHONY: clean liboqs-guard
