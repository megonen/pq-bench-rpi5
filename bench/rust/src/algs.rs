//! Algorithm drivers. Structure mirrors bench_pq.c run_kem()/run_sig():
//! correctness gate ONCE outside timing, then keygen / encaps|sign /
//! decaps|verify measured on canonical, pre-validated inputs. Output rows are
//! schema-2.0.0 JSONL with implementation:"rustcrypto" and the SAME algorithm
//! identifiers liboqs uses, so rows join across implementations by (kind, alg).
//!
//! Signing mode: HEDGED (randomized) for both ML-DSA and SLH-DSA, matching
//! liboqs 0.15.0 — verified in its vendored source: DILITHIUM_RANDOMIZED_SIGNING
//! is defined (src/sig/ml_dsa/*/config.h) and the SLH-DSA pure wrappers draw a
//! fresh addrnd via OQS_randombytes per signature (src/sig/slh_dsa/wrappers/).
//!
//! Secret-key sizes: the ml-kem/ml-dsa crates prefer SEED serialization (64/32
//! bytes) where liboqs reports the expanded FIPS encoding. `sizes.secret_key`
//! reports the EXPANDED form so the cross-implementation size check stays
//! apples-to-apples; the row carries `sk_seed_bytes` for the crate-native form.

// ExpandedKeyEncoding is deprecated upstream (seed serialization preferred);
// we use it deliberately, once, in the size gate to verify the expanded FIPS
// encoding length against liboqs.
#![allow(deprecated)]

use crate::bench::{die, must_measure, stats_json, BenchCfg};
use std::hint::black_box;

use ml_dsa::signature::{Keypair, RandomizedSigner, Verifier};
use ml_dsa::{ExpandedSigningKeyBytes, MlDsa44, MlDsa65, MlDsa87};
use ml_kem::{
    Decapsulate, Encapsulate, ExpandedKeyEncoding, Generate, Kem, KeyExport, MlKem1024, MlKem512,
    MlKem768,
};
use slh_dsa::{Sha2_128f, Sha2_128s, Sha2_192f, Sha2_256f, SigningKey as SlhSigningKey};
use ed25519_dalek::Signer as _;

/// The pure-Rust classical baselines (dalek crates), mirroring the C side's
/// OpenSSL X25519/Ed25519 rows: every implementation gets an in-family anchor
/// so cross-implementation comparisons can be expressed as ratios ("ML-KEM
/// keygen costs Nx X25519 here") that normalise whole-implementation effects.
fn run_x25519(cfg: &BenchCfg) -> i32 {
    let alg = "X25519";
    let mut rng = os_rng();

    // ---- correctness gate: ECDH must agree (bench_pq.c:498-504) ----
    let a = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let b = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let pa = x25519_dalek::PublicKey::from(&a);
    let pb = x25519_dalek::PublicKey::from(&b);
    if a.diffie_hellman(&pb).as_bytes() != b.diffie_hellman(&pa).as_bytes() {
        die(alg, "ECDH shared-secret mismatch");
    }

    // keygen = secret + public derivation, same work as the C EVP keygen
    let mut kg_rng = os_rng();
    let mut keygen = || -> Result<(), ()> {
        let s = x25519_dalek::StaticSecret::random_from_rng(&mut kg_rng);
        sink(x25519_dalek::PublicKey::from(&s));
        Ok(())
    };
    let mut derive = || -> Result<(), ()> {
        sink(a.diffie_hellman(&pb));
        Ok(())
    };

    let kg = must_measure(alg, "keygen", &mut keygen, cfg);
    let dv = must_measure(alg, "derive", &mut derive, cfg);

    let ops = render_ops(vec![("keygen", kg), ("derive", dv)]);
    // classical:true, like the C openssl baseline rows
    let mut row = String::from(
        "{\"alg\":\"X25519\",\"kind\":\"kem\",\"implementation\":\"rustcrypto\",\
         \"classical\":true,\"enabled\":true,\"claimed_nist_level\":1,\
         \"sizes\":{\"public_key\":32,\"secret_key\":32,\"ciphertext\":null,\"shared_secret\":32},\
         \"operations\":{",
    );
    for (i, block) in ops.iter().enumerate() {
        if i > 0 {
            row += ",";
        }
        row += block;
    }
    row += "}}";
    println!("{row}");
    0
}

fn run_ed25519(cfg: &BenchCfg) -> i32 {
    let alg = "Ed25519";
    let mut rng = os_rng();

    // ---- correctness gate (bench_pq.c:561-564) ----
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    let sig = sk.sign(&MSG); // deterministic RFC 8032, same as OpenSSL
    if vk.verify(&MSG, &sig).is_err() {
        die(alg, "verify failed on a valid signature (broken build)");
    }

    let vk_bytes = vk.to_bytes();

    let mut kg_rng = os_rng();
    let mut keygen = || -> Result<(), ()> {
        sink(ed25519_dalek::SigningKey::generate(&mut kg_rng));
        Ok(())
    };
    let mut sign = || -> Result<(), ()> {
        sink(sk.sign(&MSG));
        Ok(())
    };
    // verify = pk from wire bytes + verify (incl. point decompression) — the
    // TLS/OQS call shape; verify_cached_key = pre-parsed key (validator).
    let mut verify = || -> Result<(), ()> {
        match ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes) {
            Ok(v) => {
                if v.verify(&MSG, &sig).is_ok() {
                    sink(1u8);
                    Ok(())
                } else {
                    Err(())
                }
            }
            Err(_) => Err(()),
        }
    };
    let mut verify_cached = || -> Result<(), ()> {
        if vk.verify(&MSG, &sig).is_ok() {
            sink(1u8);
            Ok(())
        } else {
            Err(())
        }
    };

    let kg = must_measure(alg, "keygen", &mut keygen, cfg);
    let sg = must_measure(alg, "sign", &mut sign, cfg);
    let vf = must_measure(alg, "verify", &mut verify, cfg);
    let vc = must_measure(alg, "verify_cached_key", &mut verify_cached, cfg);

    let ops = render_ops(vec![
        ("keygen", kg),
        ("sign", sg),
        ("verify", vf),
        ("verify_cached_key", vc),
    ]);
    let mut row = String::from(
        "{\"alg\":\"Ed25519\",\"kind\":\"sig\",\"implementation\":\"rustcrypto\",\
         \"classical\":true,\"enabled\":true,\"claimed_nist_level\":1,\
         \"sizes\":{\"public_key\":32,\"secret_key\":32,\"signature\":64},\
         \"operations\":{",
    );
    for (i, block) in ops.iter().enumerate() {
        if i > 0 {
            row += ",";
        }
        row += block;
    }
    row += "}}";
    println!("{row}");
    0
}

/// bench_pq.c MSGLEN (=32) and the 0xA5 fill (:426).
const MSG: [u8; 32] = [0xA5; 32];

/// System RNG (getrandom-backed) — analogous to liboqs' default system
/// OQS_randombytes; both sides pay the system-entropy cost inside keygen/sign.
fn os_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

/// The anti-DCE sink. C uses a file-scope volatile store per op (g_sink,
/// bench_pq.c:296-300); the Rust equivalent is std::hint::black_box, which
/// forces the value to be materialized so the crypto call cannot be optimized
/// away. Applied to every timed op's output.
fn sink<T>(v: T) {
    black_box(v);
}

/// Expected sizes = the FIPS encodings, which are exactly what liboqs reports.
/// A mismatch means a bug or a spec disagreement, NOT a benchmarking result —
/// so, like the C correctness gate, it aborts with no stdout (die/exit 3).
fn check_size(alg: &str, what: &str, got: usize, want: usize) {
    if got != want {
        die(
            alg,
            &format!("size mismatch: {what} is {got} bytes, expected {want} (FIPS/liboqs)"),
        );
    }
}

pub const ALGS: &[(&str, &str)] = &[
    // classical baselines first, like the C sweep (config.yaml order)
    ("kem", "X25519"),
    ("sig", "Ed25519"),
    ("kem", "ML-KEM-512"),
    ("kem", "ML-KEM-768"),
    ("kem", "ML-KEM-1024"),
    ("sig", "ML-DSA-44"),
    ("sig", "ML-DSA-65"),
    ("sig", "ML-DSA-87"),
    ("sig", "SLH_DSA_PURE_SHA2_128F"),
    ("sig", "SLH_DSA_PURE_SHA2_128S"),
    ("sig", "SLH_DSA_PURE_SHA2_192F"),
    ("sig", "SLH_DSA_PURE_SHA2_256F"),
];

fn print_row(alg: &str, kind: &str, level: u32, sizes: &str, extra: &str, ops: &[String]) {
    let mut row = format!(
        "{{\"alg\":\"{alg}\",\"kind\":\"{kind}\",\"implementation\":\"rustcrypto\",\"enabled\":true,"
    );
    row += &format!("\"claimed_nist_level\":{level},");
    row += &format!("\"sizes\":{{{sizes}}},");
    row += extra; // e.g. "\"sk_seed_bytes\":64," or ""
    row += "\"operations\":{";
    for (i, block) in ops.iter().enumerate() {
        if i > 0 {
            row += ",";
        }
        row += block;
    }
    row += "}}";
    println!("{row}");
}

fn render_ops(alg_ops: Vec<(&str, crate::bench::MeasureOut)>) -> Vec<String> {
    alg_ops
        .into_iter()
        .map(|(name, mut m)| {
            let st = crate::bench::compute_stats(&mut m.all);
            stats_json(name, &st, &m)
        })
        .collect()
}

macro_rules! run_mlkem {
    ($K:ty, $name:expr, $level:expr, $pk:expr, $sk:expr, $ct:expr, $cfg:expr) => {{
        let alg = $name;
        let mut rng = os_rng();

        // ---- correctness gate ONCE outside timing (bench_pq.c:357-363) ----
        let (dk, ek) = <$K>::generate_keypair_from_rng(&mut rng);
        let (ct, ss_e) = ek.encapsulate_with_rng(&mut rng);
        let ss_d = dk.decapsulate(&ct);
        if ss_e != ss_d {
            die(alg, "KEM shared-secret mismatch (ss_encaps != ss_decaps)");
        }
        check_size(alg, "public_key", ek.to_bytes().len(), $pk);
        check_size(alg, "secret_key (expanded)", dk.to_expanded_bytes().len(), $sk);
        check_size(alg, "ciphertext", ct.len(), $ct);
        check_size(alg, "shared_secret", ss_e.len(), 32);
        let sk_seed = dk.to_bytes().len();

        // ---- timed ops on canonical validated inputs ----
        let mut kg_rng = os_rng();
        let mut keygen = || -> Result<(), ()> {
            sink(<$K>::generate_keypair_from_rng(&mut kg_rng));
            Ok(())
        };
        let mut en_rng = os_rng();
        let mut encaps = || -> Result<(), ()> {
            sink(ek.encapsulate_with_rng(&mut en_rng));
            Ok(())
        };
        let mut decaps = || -> Result<(), ()> {
            sink(dk.decapsulate(&ct));
            Ok(())
        };

        let kg = must_measure(alg, "keygen", &mut keygen, $cfg);
        let en = must_measure(alg, "encaps", &mut encaps, $cfg);
        let de = must_measure(alg, "decaps", &mut decaps, $cfg);

        let ops = render_ops(vec![("keygen", kg), ("encaps", en), ("decaps", de)]);
        let sizes = format!(
            "\"public_key\":{},\"secret_key\":{},\"ciphertext\":{},\"shared_secret\":32",
            $pk, $sk, $ct
        );
        let extra = format!("\"sk_seed_bytes\":{sk_seed},");
        print_row(alg, "kem", $level, &sizes, &extra, &ops);
        0
    }};
}

macro_rules! run_mldsa {
    ($P:ty, $name:expr, $level:expr, $pk:expr, $sk:expr, $sig:expr, $cfg:expr) => {{
        let alg = $name;
        let mut rng = os_rng();

        // ---- correctness gate (bench_pq.c:428-434) ----
        let sk = ml_dsa::SigningKey::<$P>::generate_from_rng(&mut rng);
        let vk = sk.verifying_key();
        let sig = match sk.expanded_key().try_sign_with_rng(&mut rng, &MSG) {
            Ok(s) => s,
            Err(_) => die(alg, "sign failed"),
        };
        if vk.verify(&MSG, &sig).is_err() {
            die(alg, "signature verify failed on a valid signature (broken build)");
        }
        check_size(alg, "public_key", vk.encode().len(), $pk);
        check_size(
            alg,
            "secret_key (expanded)",
            core::mem::size_of::<ExpandedSigningKeyBytes<$P>>(),
            $sk,
        );
        check_size(alg, "signature", sig.encode().len(), $sig);
        let sk_seed = sk.to_bytes().len();
        let vk_enc = vk.encode();

        let mut kg_rng = os_rng();
        let mut keygen = || -> Result<(), ()> {
            sink(ml_dsa::SigningKey::<$P>::generate_from_rng(&mut kg_rng));
            Ok(())
        };
        let mut sg_rng = os_rng();
        let mut sign = || -> Result<(), ()> {
            // hedged signing, matching liboqs (DILITHIUM_RANDOMIZED_SIGNING)
            match sk.expanded_key().try_sign_with_rng(&mut sg_rng, &MSG) {
                Ok(s) => {
                    sink(s);
                    Ok(())
                }
                Err(_) => Err(()),
            }
        };
        // verify = decode pk from wire bytes + verify: the shape OQS_SIG_verify
        // measures (it re-expands from pk bytes per call) and the shape TLS
        // pays per handshake. For ML-DSA the decode expands A_hat, so this is
        // materially more work than verifying with a cached key object.
        let mut verify = || -> Result<(), ()> {
            let v = ml_dsa::VerifyingKey::<$P>::decode(&vk_enc);
            if v.verify(&MSG, &sig).is_ok() {
                sink(1u8);
                Ok(())
            } else {
                Err(())
            }
        };
        // verify_cached_key = pre-parsed key object, expansion amortised: the
        // long-lived-peer (validator) pattern. verify - verify_cached_key =
        // the pk parse/expansion cost.
        let mut verify_cached = || -> Result<(), ()> {
            if vk.verify(&MSG, &sig).is_ok() {
                sink(1u8);
                Ok(())
            } else {
                Err(())
            }
        };

        let kg = must_measure(alg, "keygen", &mut keygen, $cfg);
        let sg = must_measure(alg, "sign", &mut sign, $cfg);
        let vf = must_measure(alg, "verify", &mut verify, $cfg);
        let vc = must_measure(alg, "verify_cached_key", &mut verify_cached, $cfg);

        let ops = render_ops(vec![
            ("keygen", kg),
            ("sign", sg),
            ("verify", vf),
            ("verify_cached_key", vc),
        ]);
        let sizes = format!(
            "\"public_key\":{},\"secret_key\":{},\"signature\":{}",
            $pk, $sk, $sig
        );
        let extra = format!("\"sk_seed_bytes\":{sk_seed},");
        print_row(alg, "sig", $level, &sizes, &extra, &ops);
        0
    }};
}

macro_rules! run_slhdsa {
    ($P:ty, $name:expr, $level:expr, $pk:expr, $sk:expr, $sig:expr, $cfg:expr) => {{
        let alg = $name;
        let mut rng = os_rng();

        // ---- correctness gate ----
        let sk = SlhSigningKey::<$P>::new(&mut rng);
        let vk: &slh_dsa::VerifyingKey<$P> = sk.as_ref();
        let sig = match sk.try_sign_with_rng(&mut rng, &MSG) {
            Ok(s) => s,
            Err(_) => die(alg, "sign failed"),
        };
        if vk.verify(&MSG, &sig).is_err() {
            die(alg, "signature verify failed on a valid signature (broken build)");
        }
        check_size(alg, "public_key", vk.to_bytes().len(), $pk);
        check_size(alg, "secret_key", sk.to_bytes().len(), $sk);
        check_size(alg, "signature", sig.to_bytes().len(), $sig);
        let vk_bytes = vk.to_bytes();

        let mut kg_rng = os_rng();
        let mut keygen = || -> Result<(), ()> {
            sink(SlhSigningKey::<$P>::new(&mut kg_rng));
            Ok(())
        };
        let mut sg_rng = os_rng();
        let mut sign = || -> Result<(), ()> {
            // hedged signing, matching liboqs (fresh addrnd per signature)
            match sk.try_sign_with_rng(&mut sg_rng, &MSG) {
                Ok(s) => {
                    sink(s);
                    Ok(())
                }
                Err(_) => Err(()),
            }
        };
        // verify = pk from wire bytes + verify (OQS/TLS call shape); for
        // SLH-DSA the key is two small seeds so the decode is near-free —
        // both shapes are still emitted for row-shape consistency.
        let mut verify = || -> Result<(), ()> {
            match slh_dsa::VerifyingKey::<$P>::try_from(&vk_bytes[..]) {
                Ok(v) => {
                    if v.verify(&MSG, &sig).is_ok() {
                        sink(1u8);
                        Ok(())
                    } else {
                        Err(())
                    }
                }
                Err(_) => Err(()),
            }
        };
        let mut verify_cached = || -> Result<(), ()> {
            if vk.verify(&MSG, &sig).is_ok() {
                sink(1u8);
                Ok(())
            } else {
                Err(())
            }
        };

        let kg = must_measure(alg, "keygen", &mut keygen, $cfg);
        let sg = must_measure(alg, "sign", &mut sign, $cfg);
        let vf = must_measure(alg, "verify", &mut verify, $cfg);
        let vc = must_measure(alg, "verify_cached_key", &mut verify_cached, $cfg);

        let ops = render_ops(vec![
            ("keygen", kg),
            ("sign", sg),
            ("verify", vf),
            ("verify_cached_key", vc),
        ]);
        let sizes = format!(
            "\"public_key\":{},\"secret_key\":{},\"signature\":{}",
            $pk, $sk, $sig
        );
        print_row(alg, "sig", $level, &sizes, "", &ops);
        0
    }};
}

pub fn run(kind: &str, alg: &str, cfg: &BenchCfg) -> i32 {
    match (kind, alg) {
        ("kem", "X25519") => run_x25519(cfg),
        ("sig", "Ed25519") => run_ed25519(cfg),
        ("kem", "ML-KEM-512") => run_mlkem!(MlKem512, "ML-KEM-512", 1, 800, 1632, 768, cfg),
        ("kem", "ML-KEM-768") => run_mlkem!(MlKem768, "ML-KEM-768", 3, 1184, 2400, 1088, cfg),
        ("kem", "ML-KEM-1024") => run_mlkem!(MlKem1024, "ML-KEM-1024", 5, 1568, 3168, 1568, cfg),
        ("sig", "ML-DSA-44") => run_mldsa!(MlDsa44, "ML-DSA-44", 2, 1312, 2560, 2420, cfg),
        ("sig", "ML-DSA-65") => run_mldsa!(MlDsa65, "ML-DSA-65", 3, 1952, 4032, 3309, cfg),
        ("sig", "ML-DSA-87") => run_mldsa!(MlDsa87, "ML-DSA-87", 5, 2592, 4896, 4627, cfg),
        ("sig", "SLH_DSA_PURE_SHA2_128F") => {
            run_slhdsa!(Sha2_128f, "SLH_DSA_PURE_SHA2_128F", 1, 32, 64, 17088, cfg)
        }
        ("sig", "SLH_DSA_PURE_SHA2_128S") => {
            run_slhdsa!(Sha2_128s, "SLH_DSA_PURE_SHA2_128S", 1, 32, 64, 7856, cfg)
        }
        ("sig", "SLH_DSA_PURE_SHA2_192F") => {
            run_slhdsa!(Sha2_192f, "SLH_DSA_PURE_SHA2_192F", 3, 48, 96, 35664, cfg)
        }
        ("sig", "SLH_DSA_PURE_SHA2_256F") => {
            run_slhdsa!(Sha2_256f, "SLH_DSA_PURE_SHA2_256F", 5, 64, 128, 49856, cfg)
        }
        _ => {
            // Same shape as the C harness's not-enabled row (bench_pq.c:344):
            // an algorithm this implementation cannot provide is recorded as
            // unavailable, never faked.
            println!(
                "{{\"alg\":\"{alg}\",\"kind\":\"{kind}\",\"implementation\":\"rustcrypto\",\
                 \"enabled\":false,\"reason\":\"no mature pure-Rust implementation\"}}"
            );
            0
        }
    }
}
