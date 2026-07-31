# Build the TLS handshake harness against the OpenSSL that has oqs-provider.
#   make OPENSSL_PREFIX=...   (defaults to Homebrew openssl@3.5, else system)

OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3.5 2>/dev/null || echo /usr)

CC     ?= cc
CFLAGS := -O3 -std=c11 -Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
LDLIBS  := -lssl -lcrypto -lm

bench_tls: bench_tls.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f bench_tls

.PHONY: clean
