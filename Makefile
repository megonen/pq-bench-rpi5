# =============================================================================
# pqc-bench — executable documentation. `make help` lists everything.
#
# Design rules (docs/history behind them: the cold-read round):
#   * `check` is READ-ONLY; `deps` is the only target that installs anything.
#   * No stamp files — skip decisions use live probes and real artifacts
#     (an upgraded OpenSSL or deleted toolchain always triggers a rebuild).
#   * `smoke`/`run` depend on `build` only: `test`'s hygiene checks must never
#     block a 30-minute measurement. Run `make test` before trusting results.
#   * All test artifacts live in /tmp — never results/ or bench/tls/pki/.
# =============================================================================
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help check deps build test test-fedora smoke run merge dashboard clean distclean

help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

check: ## verify the environment (read-only; prints per-platform install hints)
	@scripts/check-env.sh

deps: ## OPT-IN: install missing system deps (brew/apt/dnf); add RUST=1 for rustup
	@scripts/install-deps.sh

build: check ## C toolchain (liboqs/OpenSSL/oqs-provider) + bench binaries + Rust harnesses
	@scripts/build-toolchain.sh

test: build ## fast verification gate (~1-2 min): correctness blocks, hygiene warns
	@scripts/selftest.sh

test-fedora: ## check/build/test in a Fedora container (Red Hat paths/packages/degradation; SMOKE=1 adds a smoke run; not a benchmark)
	@scripts/test-fedora.sh

smoke: build ## all-four-groups smoke benchmark (1 rep, 50 handshakes/cell)
	@scripts/bench-run.sh --smoke

run: build ## full benchmark run (~30 min Pi / ~36 min M3); sudo handled per-platform
	@scripts/bench-run.sh

merge: ## regenerate dashboard/data/merged.json from the published_runs manifest
	python3 analyze/merge.py

dashboard: ## serve the dashboard over HTTP (does NOT touch merged.json; see 'merge')
	@echo "serving http://localhost:8000 (Ctrl-C to stop)"
	@cd dashboard && python3 -m http.server 8000

clean: ## remove bench binaries and Rust target trees
	$(MAKE) -C bench/kem_sig clean
	$(MAKE) -C bench/tls clean
	rm -rf bench/rust/target bench/rust-tls/target

distclean: clean ## additionally remove the vendored C toolchain (forces full rebuild)
	rm -rf vendor setup/versions.lock
