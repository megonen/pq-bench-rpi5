//! aws-lc-rs primitive rows (implementation:"aws-lc-rs") — measured to PRICE
//! the rustls-awslc handshake primitive sums, NOT as an independent
//! implementation: aws-lc-rs wraps the AWS-LC C library, which is exactly why
//! Stage 3 excluded it from the pure-Rust group. Same bench_pq methodology
//! (bench.rs), same row shape, same algorithm identifiers.
//!
//! Semantics: verify is FROM-BYTES by construction (aws-lc-rs
//! UnparsedPublicKey parses the key per call), matching OQS_SIG_verify and
//! the per-handshake TLS pattern. ML-DSA signing is hedged (FIPS 204 default
//! inside AWS-LC). X25519/P-256 derive parses the peer key per call, matching
//! bench_pq.c's per-call EVP_PKEY_derive_set_peer.

use crate::bench::{compute_stats, die, must_measure, stats_json, BenchCfg, MeasureOut};
use aws_lc_rs::unstable::signature as pq;
use aws_lc_rs::{agreement, kem, signature};
use std::hint::black_box;

const MSG: [u8; 32] = [0xA5; 32];

pub const PRIMS: &[(&str, &str)] = &[
    ("kem", "X25519"),
    ("kem", "secp256r1"),
    ("kem", "ML-KEM-768"),
    ("kem", "ML-KEM-1024"),
    ("sig", "Ed25519"),
    ("sig", "ML-DSA-44"),
    ("sig", "ML-DSA-65"),
    ("sig", "ML-DSA-87"),
];

fn sink<T>(v: T) {
    black_box(v);
}

fn check_size(alg: &str, what: &str, got: usize, want: usize) {
    if got != want {
        die(
            alg,
            &format!("size mismatch: {what} is {got} bytes, expected {want} (FIPS/liboqs)"),
        );
    }
}

fn print_row(alg: &str, kind: &str, level: u32, classical: bool, sizes: &str, ops: &[String]) {
    let mut row = format!(
        "{{\"alg\":\"{alg}\",\"kind\":\"{kind}\",\"implementation\":\"aws-lc-rs\","
    );
    if classical {
        row += "\"classical\":true,";
    }
    row += &format!("\"enabled\":true,\"claimed_nist_level\":{level},");
    row += &format!("\"sizes\":{{{sizes}}},");
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

fn render(ops: Vec<(&str, MeasureOut)>) -> Vec<String> {
    ops.into_iter()
        .map(|(name, mut m)| {
            let st = compute_stats(&mut m.all);
            stats_json(name, &st, &m)
        })
        .collect()
}

fn run_mlkem(alg_name: &str, alg: &'static kem::Algorithm, level: u32, pk: usize, ct: usize, cfg: &BenchCfg) -> i32 {
    // correctness gate (mirrors bench_pq.c)
    let dk = kem::DecapsulationKey::generate(alg).unwrap_or_else(|_| die(alg_name, "keygen failed"));
    let ek = dk.encapsulation_key().unwrap_or_else(|_| die(alg_name, "encapsulation key failed"));
    let (ct0, ss_e) = ek.encapsulate().unwrap_or_else(|_| die(alg_name, "encaps failed"));
    let ss_d = dk
        .decapsulate(ct0.as_ref().into())
        .unwrap_or_else(|_| die(alg_name, "decaps failed"));
    if ss_e.as_ref() != ss_d.as_ref() {
        die(alg_name, "KEM shared-secret mismatch (ss_encaps != ss_decaps)");
    }
    check_size(alg_name, "public_key",
               ek.key_bytes().map(|b| b.as_ref().len()).unwrap_or(0), pk);
    check_size(alg_name, "ciphertext", ct0.as_ref().len(), ct);
    check_size(alg_name, "shared_secret", ss_e.as_ref().len(), 32);
    let ct_bytes = ct0.as_ref().to_vec();

    let mut keygen = || -> Result<(), ()> {
        sink(kem::DecapsulationKey::generate(alg).map_err(|_| ())?);
        Ok(())
    };
    let mut encaps = || -> Result<(), ()> {
        sink(ek.encapsulate().map_err(|_| ())?);
        Ok(())
    };
    let mut decaps = || -> Result<(), ()> {
        sink(dk.decapsulate(ct_bytes.as_slice().into()).map_err(|_| ())?);
        Ok(())
    };
    let kg = must_measure(alg_name, "keygen", &mut keygen, cfg);
    let en = must_measure(alg_name, "encaps", &mut encaps, cfg);
    let de = must_measure(alg_name, "decaps", &mut decaps, cfg);
    // aws-lc-rs does not expose the expanded FIPS secret key; secret_key is
    // omitted (never guessed) so the cross-implementation size check compares
    // only fields both sides actually report.
    let sizes = format!("\"public_key\":{pk},\"ciphertext\":{ct},\"shared_secret\":32");
    print_row(alg_name, "kem", level, false, &sizes,
              &render(vec![("keygen", kg), ("encaps", en), ("decaps", de)]));
    0
}

fn run_mldsa(alg_name: &str, signing: &'static pq::PqdsaSigningAlgorithm,
             verif: &'static pq::PqdsaVerificationAlgorithm, level: u32,
             pk: usize, sig_len: usize, cfg: &BenchCfg) -> i32 {
    use aws_lc_rs::signature::KeyPair as _;
    let kp = pq::PqdsaKeyPair::generate(signing).unwrap_or_else(|_| die(alg_name, "keygen failed"));
    let pk_bytes = kp.public_key().as_ref().to_vec();
    let mut sig_buf = vec![0u8; sig_len + 64];
    let n = kp.sign(&MSG, &mut sig_buf).unwrap_or_else(|_| die(alg_name, "sign failed"));
    sig_buf.truncate(n);
    if signature::UnparsedPublicKey::new(verif, &pk_bytes)
        .verify(&MSG, &sig_buf)
        .is_err()
    {
        die(alg_name, "verify failed on a valid signature (broken build)");
    }
    check_size(alg_name, "public_key", pk_bytes.len(), pk);
    check_size(alg_name, "signature", sig_buf.len(), sig_len);

    let mut keygen = || -> Result<(), ()> {
        sink(pq::PqdsaKeyPair::generate(signing).map_err(|_| ())?);
        Ok(())
    };
    let mut buf = vec![0u8; sig_len + 64];
    let mut sign = || -> Result<(), ()> {
        // hedged per FIPS 204 (AWS-LC's default signing mode)
        let n = kp.sign(&MSG, &mut buf).map_err(|_| ())?;
        sink(buf[..n].first().copied());
        Ok(())
    };
    let mut verify = || -> Result<(), ()> {
        // from-bytes per call: UnparsedPublicKey parses + verifies
        signature::UnparsedPublicKey::new(verif, &pk_bytes)
            .verify(&MSG, &sig_buf)
            .map_err(|_| ())?;
        sink(1u8);
        Ok(())
    };
    let kg = must_measure(alg_name, "keygen", &mut keygen, cfg);
    let sg = must_measure(alg_name, "sign", &mut sign, cfg);
    let vf = must_measure(alg_name, "verify", &mut verify, cfg);
    let sizes = format!("\"public_key\":{pk},\"signature\":{sig_len}");
    print_row(alg_name, "sig", level, false, &sizes,
              &render(vec![("keygen", kg), ("sign", sg), ("verify", vf)]));
    0
}

fn run_ecdh(alg_name: &str, alg: &'static agreement::Algorithm, pk_len: usize, cfg: &BenchCfg) -> i32 {
    let sk = agreement::PrivateKey::generate(alg).unwrap_or_else(|_| die(alg_name, "keygen failed"));
    let peer = agreement::PrivateKey::generate(alg).unwrap_or_else(|_| die(alg_name, "peer keygen failed"));
    let my_pub = sk.compute_public_key().unwrap_or_else(|_| die(alg_name, "pubkey failed"));
    let peer_pub = peer
        .compute_public_key()
        .unwrap_or_else(|_| die(alg_name, "peer pubkey failed"));
    check_size(alg_name, "public_key", my_pub.as_ref().len(), pk_len);
    // ECDH must agree (mirrors bench_pq.c:498-504)
    let s1 = agreement::agree(&sk, agreement::UnparsedPublicKey::new(alg, peer_pub.as_ref()),
                              (), |s| Ok::<Vec<u8>, ()>(s.to_vec()))
        .unwrap_or_else(|_| die(alg_name, "derive(self,peer) failed"));
    let s2 = agreement::agree(&peer, agreement::UnparsedPublicKey::new(alg, my_pub.as_ref()),
                              (), |s| Ok::<Vec<u8>, ()>(s.to_vec()))
        .unwrap_or_else(|_| die(alg_name, "derive(peer,self) failed"));
    if s1 != s2 {
        die(alg_name, "ECDH shared-secret mismatch");
    }
    let peer_bytes = peer_pub.as_ref().to_vec();

    let mut keygen = || -> Result<(), ()> {
        let k = agreement::PrivateKey::generate(alg).map_err(|_| ())?;
        sink(k.compute_public_key().map_err(|_| ())?);
        Ok(())
    };
    let mut derive = || -> Result<(), ()> {
        // peer key parsed per call, matching bench_pq.c's per-call set_peer
        agreement::agree(&sk, agreement::UnparsedPublicKey::new(alg, &peer_bytes),
                         (), |s| {
                             sink(s[0]);
                             Ok::<(), ()>(())
                         })
    };
    let kg = must_measure(alg_name, "keygen", &mut keygen, cfg);
    let dv = must_measure(alg_name, "derive", &mut derive, cfg);
    let ss_len = s1.len();
    let sizes = format!(
        "\"public_key\":{pk_len},\"ciphertext\":null,\"shared_secret\":{ss_len}"
    );
    print_row(alg_name, "kem", 1, true, &sizes, &render(vec![("keygen", kg), ("derive", dv)]));
    0
}

fn run_ed25519(cfg: &BenchCfg) -> i32 {
    use aws_lc_rs::signature::KeyPair as _;
    let alg_name = "Ed25519";
    let kp = signature::Ed25519KeyPair::generate().unwrap_or_else(|_| die(alg_name, "keygen failed"));
    let pk_bytes = kp.public_key().as_ref().to_vec();
    let sig = kp.sign(&MSG);
    if signature::UnparsedPublicKey::new(&signature::ED25519, &pk_bytes)
        .verify(&MSG, sig.as_ref())
        .is_err()
    {
        die(alg_name, "verify failed on a valid signature (broken build)");
    }
    check_size(alg_name, "public_key", pk_bytes.len(), 32);
    check_size(alg_name, "signature", sig.as_ref().len(), 64);
    let sig_bytes = sig.as_ref().to_vec();

    let mut keygen = || -> Result<(), ()> {
        sink(signature::Ed25519KeyPair::generate().map_err(|_| ())?);
        Ok(())
    };
    let mut sign = || -> Result<(), ()> {
        sink(kp.sign(&MSG));
        Ok(())
    };
    let mut verify = || -> Result<(), ()> {
        signature::UnparsedPublicKey::new(&signature::ED25519, &pk_bytes)
            .verify(&MSG, &sig_bytes)
            .map_err(|_| ())?;
        sink(1u8);
        Ok(())
    };
    let kg = must_measure(alg_name, "keygen", &mut keygen, cfg);
    let sg = must_measure(alg_name, "sign", &mut sign, cfg);
    let vf = must_measure(alg_name, "verify", &mut verify, cfg);
    print_row(alg_name, "sig", 1, true,
              "\"public_key\":32,\"secret_key\":32,\"signature\":64",
              &render(vec![("keygen", kg), ("sign", sg), ("verify", vf)]));
    0
}

pub fn run(kind: &str, alg: &str, cfg: &BenchCfg) -> i32 {
    match (kind, alg) {
        ("kem", "X25519") => run_ecdh("X25519", &agreement::X25519, 32, cfg),
        ("kem", "secp256r1") => run_ecdh("secp256r1", &agreement::ECDH_P256, 65, cfg),
        ("kem", "ML-KEM-768") => run_mlkem("ML-KEM-768", &kem::ML_KEM_768, 3, 1184, 1088, cfg),
        ("kem", "ML-KEM-1024") => run_mlkem("ML-KEM-1024", &kem::ML_KEM_1024, 5, 1568, 1568, cfg),
        ("sig", "Ed25519") => run_ed25519(cfg),
        ("sig", "ML-DSA-44") => {
            run_mldsa("ML-DSA-44", &pq::ML_DSA_44_SIGNING, &pq::ML_DSA_44, 2, 1312, 2420, cfg)
        }
        ("sig", "ML-DSA-65") => {
            run_mldsa("ML-DSA-65", &pq::ML_DSA_65_SIGNING, &pq::ML_DSA_65, 3, 1952, 3309, cfg)
        }
        ("sig", "ML-DSA-87") => {
            run_mldsa("ML-DSA-87", &pq::ML_DSA_87_SIGNING, &pq::ML_DSA_87, 5, 2592, 4627, cfg)
        }
        _ => {
            println!(
                "{{\"alg\":\"{alg}\",\"kind\":\"{kind}\",\"implementation\":\"aws-lc-rs\",\
                 \"enabled\":false,\"reason\":\"not measured in the aws-lc-rs pricing set\"}}"
            );
            0
        }
    }
}
