//! pqb-rust — pure-Rust (RustCrypto) KEM/signature harness.
//!
//! One algorithm per invocation (fresh process keeps cache state clean), same
//! CLI, same auto-calibration and same statistics as bench/kem_sig/bench_pq.c
//! (see bench.rs for the line-by-line mapping). Emits one schema-2.0.0 JSONL
//! row with implementation:"rustcrypto" to stdout.
//!
//!   pqb-rust --kind kem --alg ML-KEM-768 --target-time-ms 250 \
//!            --min-samples 30 --max-iters 20000 --reps 5
//!   pqb-rust --list          # kind<TAB>alg lines for run.sh
//!   pqb-rust --provenance    # Rust toolchain/code-path provenance JSON

mod algs;
mod bench;

use bench::BenchCfg;
use std::process::exit;

fn provenance_json() -> String {
    let compiled: Vec<String> = env!("PQB_TARGET_FEATURES")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| format!("\"{s}\""))
        .collect();

    #[cfg(target_arch = "aarch64")]
    let runtime = format!(
        "{{\"neon\":{},\"aes\":{},\"sha2\":{},\"sha3\":{}}}",
        std::arch::is_aarch64_feature_detected!("neon"),
        std::arch::is_aarch64_feature_detected!("aes"),
        std::arch::is_aarch64_feature_detected!("sha2"),
        std::arch::is_aarch64_feature_detected!("sha3"),
    );
    #[cfg(not(target_arch = "aarch64"))]
    let runtime = "null".to_string();

    format!(
        concat!(
            "{{\"available\":true,",
            "\"rustc_version\":\"{}\",",
            "\"target\":\"{}\",",
            "\"profile\":\"{}\",",
            "\"opt_level\":\"{}\",",
            "\"codegen_units\":1,",
            "\"lto\":false,",
            "\"rustflags\":\"{}\",",
            "\"target_features_compiled\":[{}],",
            "\"cpu_features_runtime\":{},",
            "\"crate_versions\":{{\"ml-kem\":\"{}\",\"ml-dsa\":\"{}\",\"slh-dsa\":\"{}\",",
            "\"x25519-dalek\":\"{}\",\"ed25519-dalek\":\"{}\"}},",
            "\"signing_mode\":\"hedged (randomized), matching liboqs 0.15.0 for both ML-DSA and SLH-DSA\",",
            "\"verify_semantics\":\"verify = decode public key from wire bytes + verify \
             (matches OQS_SIG_verify, which re-expands from pk bytes per call, and the \
             per-handshake TLS pattern); verify_cached_key = pre-parsed key object with \
             expansion amortised (long-lived-peer/validator pattern); the difference is \
             the pk parse/expansion cost\",",
            "\"code_path_note\":\"{}\"}}"
        ),
        env!("PQB_RUSTC_VERSION"),
        env!("PQB_TARGET"),
        env!("PQB_PROFILE"),
        env!("PQB_OPT_LEVEL"),
        env!("PQB_RUSTFLAGS"),
        compiled.join(","),
        runtime,
        env!("PQB_CRATE_ML_KEM"),
        env!("PQB_CRATE_ML_DSA"),
        env!("PQB_CRATE_SLH_DSA"),
        env!("PQB_CRATE_X25519_DALEK"),
        env!("PQB_CRATE_ED25519_DALEK"),
        // Kept factual and verified against the crate sources in the resolved
        // dependency tree; the Rust-side analogue of toolchain.liboqs_opt_defines.
        "arithmetic kernels of ml-kem/ml-dsa/slh-dsa are portable Rust with no \
         hand-written assembly and no explicit SIMD intrinsics (compiler \
         autovectorisation only, per RUSTFLAGS/target-cpu above) - unlike \
         liboqs, which has dedicated aarch64 asm for ML-KEM (mlkem-native); \
         hashing uses the RustCrypto sha2 0.11 / keccak 0.2 crates, BOTH of \
         which dispatch to aarch64 hardware hash instructions via cpufeatures \
         runtime detection (SHA-2 everywhere it exists; ARMv8.2 SHA3/Keccak \
         where the CPU has it, e.g. Apple M-series but NOT Cortex-A76) - \
         symmetric with liboqs' hardware-hashing behaviour on both targets",
    )
}

fn usage() {
    eprintln!(
        "usage: pqb-rust --kind kem|sig --alg NAME [options]\n\
         \x20 same sizing options as bench_pq: --target-time-ms N --min-samples N\n\
         \x20 --max-iters N --reps N | fixed: --iters N --warmup N\n\
         \x20 also: --list | --provenance"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut kind = String::new();
    let mut alg = String::new();
    let (mut warmup, mut iters, mut reps) = (1000u64, 0u64, 5u64);
    let (mut target_time_ms, mut min_samples, mut max_iters) = (250u64, 30u64, 20000u64);

    let mut i = 1;
    while i < args.len() {
        let need = |i: usize| -> &str {
            if i + 1 < args.len() {
                &args[i + 1]
            } else {
                usage();
                exit(2);
            }
        };
        match args[i].as_str() {
            "--list" => {
                for (k, a) in algs::ALGS {
                    println!("{k}\t{a}");
                }
                return;
            }
            "--provenance" => {
                println!("{}", provenance_json());
                return;
            }
            "--kind" => {
                kind = need(i).to_string();
                i += 1;
            }
            "--alg" => {
                alg = need(i).to_string();
                i += 1;
            }
            "--warmup" => {
                warmup = need(i).parse().unwrap_or(1000);
                i += 1;
            }
            "--iters" => {
                iters = need(i).parse().unwrap_or(0);
                i += 1;
            }
            "--reps" => {
                reps = need(i).parse().unwrap_or(5);
                i += 1;
            }
            "--target-time-ms" => {
                target_time_ms = need(i).parse().unwrap_or(250);
                i += 1;
            }
            "--min-samples" => {
                min_samples = need(i).parse().unwrap_or(30);
                i += 1;
            }
            "--max-iters" => {
                max_iters = need(i).parse().unwrap_or(20000);
                i += 1;
            }
            _ => {
                usage();
                exit(2);
            }
        }
        i += 1;
    }
    if kind.is_empty() || alg.is_empty() {
        usage();
        exit(2);
    }
    let reps = reps.max(1);
    let min_samples = min_samples.max(1);
    let max_iters = max_iters.max(min_samples);

    let cfg = BenchCfg {
        fixed_iters: iters,
        target_ns: target_time_ms * 1_000_000,
        min_samples,
        max_iters,
        warmup,
        reps,
    };
    if iters > 0 {
        eprintln!("[pqb-rust] mode=fixed-count reps={reps} warmup={warmup} iters={iters}");
    } else {
        eprintln!(
            "[pqb-rust] mode=auto-calibrate reps={reps} target={target_time_ms}ms \
             min_samples={min_samples} max_iters={max_iters}"
        );
    }
    exit(algs::run(&kind, &alg, &cfg));
}
