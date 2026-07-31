#!/usr/bin/env python3
"""list_algs.py — expand config.yaml into shell-consumable lines for run.sh.

Modes:
  measurement   -> KEY=VALUE lines (auto-calib: target/min_samples/max_iters/
                   reps/cycles_mode; plus warmup/iters fixed-count fallback)
  kemsig        -> one "kind<TAB>alg<TAB>is_classical" line per algorithm,
                   baselines first (so charts always have the reference point)
  tls           -> emits the TLS matrix as JSON on one line

Uses the dependency-free miniyaml parser so no PyYAML is required.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniyaml  # noqa: E402


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "kemsig"
    cfg_path = sys.argv[2] if len(sys.argv) > 2 else "config.yaml"
    cfg = miniyaml.load_file(cfg_path)

    if mode == "measurement":
        m = cfg.get("measurement", {}) or {}
        # auto-calibration knobs (default path)
        print(f"TARGET_TIME_MS={m.get('target_time_ms', 250)}")
        print(f"MIN_SAMPLES={m.get('min_samples', 30)}")
        print(f"MAX_ITERS={m.get('max_iters', 20000)}")
        print(f"REPS={m.get('repetitions', 5)}")
        print(f"CYCLES_MODE={m.get('cycles_mode', 'auto')}")
        # fixed-count fallback knobs (used only with ./run.sh --iters)
        print(f"WARMUP={m.get('warmup_iters', 1000)}")
        print(f"ITERS={m.get('timed_iters', 10000)}")

    elif mode == "kemsig":
        for kind in ("kem", "sig"):
            section = cfg.get(kind, {}) or {}
            for grp in ("baseline", "candidates"):
                for item in (section.get(grp) or []):
                    if isinstance(item, dict):
                        name = item.get("name")
                        classical = "1" if item.get("classical") else "0"
                    else:
                        name, classical = item, "0"
                    if name:
                        print(f"{kind}\t{name}\t{classical}")

    elif mode == "tls":
        print(json.dumps(cfg.get("tls", {})))

    else:
        sys.exit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()
