//! pqb-rust-tls — rustls + aws-lc-rs TLS 1.3 handshake harness.
//!
//! Deliberately mirrors bench/tls/bench_tls.c: full TLS 1.3 handshakes
//! entirely in-process over in-memory buffers (no sockets), the same clock
//! (clock_gettime(CLOCK_MONOTONIC)), the same fixed connections+warmup loop,
//! the same statistics (median/p95/min/max/mean/sample-stddev, hs/sec), the
//! same bytes-on-wire and first-flight ClientHello accounting, and the same
//! row shape — with implementation:"rustls-awslc".
//!
//! Caveat recorded here and in the README: rustls-vs-OpenSSL is two protocol
//! implementations AND two crypto backends (aws-lc-rs vs OpenSSL native);
//! this comparison cannot separate those variables, and it is NOT a
//! language comparison.
//!
//! Phase-2 rows ride UNSTABLE cargo features (rustls-post-quantum's
//! aws-lc-rs-unstable -> aws-lc-rs "unstable" ML-DSA); such rows carry
//! "unstable_features": true.

mod bench;
mod primitives;

use std::fmt::Write as _;
use std::process::exit;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

const TYPICAL_MSS: usize = 1400; // same fragmentation note threshold as C

/// bench_tls.c now_ns(): clock_gettime(CLOCK_MONOTONIC) via libc (same clock).
fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// bench_tls.c pct(): percentile with linear interpolation on sorted samples.
fn pct(s: &[u64], p: f64) -> f64 {
    let n = s.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return s[0] as f64;
    }
    let idx = p * (n - 1) as f64;
    let lo = idx as usize;
    let f = idx - lo as f64;
    if lo + 1 >= n {
        return s[n - 1] as f64;
    }
    s[lo] as f64 + f * (s[lo + 1] as f64 - s[lo] as f64)
}

struct Cell<'a> {
    label: &'a str,
    group: &'a str,
    sig_alg: &'a str,
    phase: &'a str,
    unstable: bool,
}

fn disabled_row(c: &Cell, reason: &str) {
    println!(
        "{{\"label\":\"{}\",\"group\":\"{}\",\"sig_alg\":\"{}\",\"phase\":\"{}\",\
         \"implementation\":\"rustls-awslc\",\"unstable_features\":{},\"enabled\":false,\
         \"have_oqs_provider\":false,\"reason\":\"{}\"}}",
        c.label, c.group, c.sig_alg, c.phase, c.unstable, reason
    );
}

/// Map a group name (native-OpenSSL spelling, case-insensitive) to the rustls
/// aws-lc-rs kx group. None => not supported by this stack (a finding, emitted
/// as an enabled:false row, never papered over).
fn kx_for(name: &str) -> Option<&'static dyn rustls::crypto::SupportedKxGroup> {
    use rustls::crypto::aws_lc_rs::kx_group as kx;
    match name.to_lowercase().replace(['-', '_'], "").as_str() {
        "x25519" => Some(kx::X25519),
        "secp256r1" => Some(kx::SECP256R1),
        "x25519mlkem768" => Some(kx::X25519MLKEM768),
        "secp256r1mlkem768" => Some(kx::SECP256R1MLKEM768),
        "mlkem768" => Some(kx::MLKEM768),
        "mlkem1024" => Some(kx::MLKEM1024),
        _ => None,
    }
}

fn load_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs {path}: {e}"))
}

fn load_pem_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| format!("parse key {path}: {e}"))?
        .ok_or_else(|| format!("no private key in {path}"))
}

/// One full handshake, mirroring bench_tls.c one_handshake(): connection
/// construction inside the timed region, bytes shuttled through in-memory
/// buffers, first client flight recorded as the ClientHello size.
fn one_handshake(
    cc: &Arc<ClientConfig>,
    sc: &Arc<ServerConfig>,
    c2s: &mut usize,
    s2c: &mut usize,
    chello: &mut usize,
) -> Result<(), ()> {
    let name = ServerName::try_from("localhost").map_err(|_| ())?;
    let mut cli = ClientConnection::new(cc.clone(), name).map_err(|_| ())?;
    let mut srv = ServerConnection::new(sc.clone()).map_err(|_| ())?;
    *c2s = 0;
    *s2c = 0;
    *chello = 0;
    let mut first_flight = true;
    for i in 0..64 {
        let mut buf: Vec<u8> = Vec::new();
        while cli.wants_write() {
            cli.write_tls(&mut buf).map_err(|_| ())?;
        }
        if first_flight && !buf.is_empty() {
            *chello = buf.len();
            first_flight = false;
        }
        *c2s += buf.len();
        let mut rd = &buf[..];
        while !rd.is_empty() {
            if srv.read_tls(&mut rd).map_err(|_| ())? == 0 {
                break;
            }
        }
        srv.process_new_packets().map_err(|_| ())?;

        let mut sbuf: Vec<u8> = Vec::new();
        while srv.wants_write() {
            srv.write_tls(&mut sbuf).map_err(|_| ())?;
        }
        *s2c += sbuf.len();
        let mut rd2 = &sbuf[..];
        while !rd2.is_empty() {
            if cli.read_tls(&mut rd2).map_err(|_| ())? == 0 {
                break;
            }
        }
        cli.process_new_packets().map_err(|_| ())?;

        if !cli.is_handshaking() && !srv.is_handshaking() {
            return Ok(());
        }
        if buf.is_empty() && sbuf.is_empty() && i > 4 {
            return Err(()); // both stalled with nothing to transfer
        }
    }
    Err(())
}

fn provenance() {
    println!(
        "{{\"available\":true,\"rustc_version\":\"{}\",\"target\":\"{}\",\
         \"profile\":\"{}\",\"opt_level\":\"{}\",\"codegen_units\":1,\"lto\":false,\
         \"rustflags\":\"{}\",\
         \"crate_versions\":{{\"rustls\":\"{}\",\"rustls-post-quantum\":\"{}\",\"aws-lc-rs\":\"{}\",\"aws-lc-sys\":\"{}\"}},\
         \"unstable_features\":[\"rustls-post-quantum/aws-lc-rs-unstable (ML-DSA signing + webpki verification)\"],\
         \"note\":\"rustls-vs-OpenSSL compares two protocol implementations AND two \
crypto backends (aws-lc-rs vs OpenSSL native) at once; the variables are \
not separable from these rows and this is not a language comparison. \
aws-lc-rs wraps the AWS-LC C library - this TLS group makes no \
pure-Rust/independence claim (unlike bench/rust).\"}}",
        env!("PQB_RUSTC_VERSION"),
        env!("PQB_TARGET"),
        env!("PQB_PROFILE"),
        env!("PQB_OPT_LEVEL"),
        env!("PQB_RUSTFLAGS"),
        env!("PQB_CRATE_RUSTLS"),
        env!("PQB_CRATE_RUSTLS_POST_QUANTUM"),
        env!("PQB_CRATE_AWS_LC_RS"),
        env!("PQB_CRATE_AWS_LC_SYS"),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mut group, mut ca, mut cert, mut key, mut label) = (
        String::from("X25519"),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    let (mut phase, mut sig_alg) = (String::new(), String::new());
    let (mut connections, mut warmup) = (1000u64, 20u64);
    // primitive mode (aws-lc-rs pricing rows): --kind/--alg + bench_pq sizing
    let (mut kind, mut alg) = (String::new(), String::new());
    let (mut p_warmup, mut p_iters, mut p_reps) = (1000u64, 0u64, 5u64);
    let (mut target_time_ms, mut min_samples, mut max_iters) = (250u64, 30u64, 20000u64);
    let mut i = 1;
    while i < args.len() {
        let need = |i: usize| -> &str {
            if i + 1 < args.len() {
                &args[i + 1]
            } else {
                eprintln!("missing value for {}", args[i]);
                exit(2);
            }
        };
        match args[i].as_str() {
            "--provenance" => {
                provenance();
                return;
            }
            "--list-primitives" => {
                for (k, a) in primitives::PRIMS {
                    println!("{k}\t{a}");
                }
                return;
            }
            "--kind" => {
                kind = need(i).into();
                i += 1;
            }
            "--alg" => {
                alg = need(i).into();
                i += 1;
            }
            "--iters" => {
                p_iters = need(i).parse().unwrap_or(0);
                i += 1;
            }
            "--reps" => {
                p_reps = need(i).parse().unwrap_or(5);
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
            "--group" => {
                group = need(i).into();
                i += 1;
            }
            "--ca" => {
                ca = need(i).into();
                i += 1;
            }
            "--cert" => {
                cert = need(i).into();
                i += 1;
            }
            "--key" => {
                key = need(i).into();
                i += 1;
            }
            "--connections" => {
                connections = need(i).parse().unwrap_or(1000);
                i += 1;
            }
            "--warmup" => {
                let v: u64 = need(i).parse().unwrap_or(20);
                warmup = v;
                p_warmup = v;
                i += 1;
            }
            "--label" => {
                label = need(i).into();
                i += 1;
            }
            "--phase" => {
                phase = need(i).into();
                i += 1;
            }
            "--sig-alg" => {
                sig_alg = need(i).into();
                i += 1;
            }
            "--implementation" => {
                i += 1; // accepted for CLI parity; always rustls-awslc
            }
            other => {
                eprintln!("bad arg {other}");
                exit(2);
            }
        }
        i += 1;
    }
    // primitive mode: aws-lc-rs pricing rows, same engine as bench_pq
    if !kind.is_empty() || !alg.is_empty() {
        if kind.is_empty() || alg.is_empty() {
            eprintln!("--kind and --alg must be given together");
            exit(2);
        }
        let cfg = bench::BenchCfg {
            fixed_iters: p_iters,
            target_ns: target_time_ms * 1_000_000,
            min_samples: min_samples.max(1),
            max_iters: max_iters.max(min_samples.max(1)),
            warmup: p_warmup,
            reps: p_reps.max(1),
        };
        exit(primitives::run(&kind, &alg, &cfg));
    }
    if cert.is_empty() || key.is_empty() {
        eprintln!("--cert and --key required");
        exit(2);
    }
    // phase-2 (ML-DSA) rows ride the unstable aws-lc-rs path
    let sl = sig_alg.to_lowercase();
    let unstable = sl.contains("dsa") && !sl.contains("ed25519");
    let cell = Cell {
        label: &label,
        group: &group,
        sig_alg: &sig_alg,
        phase: &phase,
        unstable,
    };

    let Some(kx) = kx_for(&group) else {
        disabled_row(&cell, "kex group not supported by rustls 0.23 / aws-lc-rs");
        return;
    };

    // provider: rustls-post-quantum's aws-lc-rs provider (adds ML-DSA
    // signing/verification behind the unstable feature), restricted to
    // exactly the one kx group under test.
    let base = rustls_post_quantum::provider();
    let provider = Arc::new(CryptoProvider {
        kx_groups: vec![kx],
        ..base
    });

    let (chain, key_der, ca_ders) =
        match (load_pem_certs(&cert), load_pem_key(&key), load_pem_certs(&ca)) {
            (Ok(c), Ok(k), Ok(a)) if !c.is_empty() && !a.is_empty() => (c, k, a),
            (c, k, a) => {
                let mut why = String::new();
                for e in [c.err(), a.err()].into_iter().flatten() {
                    why += &e;
                }
                if let Err(e) = k {
                    why += &e;
                }
                disabled_row(&cell, &format!("cert-load-failed {}", why.replace('"', "'")));
                return;
            }
        };

    let mut roots = RootCertStore::empty();
    for der in ca_ders {
        if roots.add(der).is_err() {
            disabled_row(&cell, "ca-load-failed");
            return;
        }
    }

    // NB: rustls clients RESUME by default (in-memory ticket store on the
    // ClientConfig) — with a shared config the warmup handshakes would seed
    // tickets and every timed handshake would be a PSK resumption with no
    // certificate at all (caught via bytes_on_wire: phase2 rows measured
    // byte-identical to phase0). bench_tls.c's OpenSSL clients never resume
    // (no SSL_set_session), so resumption must be OFF for parity: every
    // timed handshake is a full handshake that transfers and verifies the
    // certificate chain.
    let cconf = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map(|b| {
            let mut c = b.with_root_certificates(roots).with_no_client_auth();
            c.resumption = rustls::client::Resumption::disabled();
            c
        });
    let sconf = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())
        .and_then(|b| {
            b.with_no_client_auth()
                .with_single_cert(chain, key_der)
                .map_err(|e| e.to_string())
        });
    let (cconf, sconf) = match (cconf, sconf) {
        (Ok(c), Ok(s)) => (Arc::new(c), Arc::new(s)),
        (c, s) => {
            let mut why = String::new();
            if let Err(e) = c {
                why += &e.to_string();
            }
            if let Err(e) = s {
                why += &e;
            }
            disabled_row(&cell, &format!("config-setup-failed {}", why.replace('"', "'")));
            return;
        }
    };

    // warmup (mirrors bench_tls.c: any warmup failure -> disabled row)
    let (mut c2s, mut s2c, mut ch) = (0usize, 0usize, 0usize);
    for _ in 0..warmup {
        if one_handshake(&cconf, &sconf, &mut c2s, &mut s2c, &mut ch).is_err() {
            disabled_row(&cell, "handshake failed");
            return;
        }
    }

    let mut lat: Vec<u64> = Vec::with_capacity(connections as usize);
    let (mut ch_last, mut c2s_last, mut s2c_last) = (0usize, 0usize, 0usize);
    for _ in 0..connections {
        let t0 = now_ns();
        let rc = one_handshake(&cconf, &sconf, &mut c2s, &mut s2c, &mut ch);
        let dt = now_ns() - t0;
        if rc.is_ok() {
            lat.push(dt);
            ch_last = ch;
            c2s_last = c2s;
            s2c_last = s2c;
        }
    }
    if lat.is_empty() {
        eprintln!("all handshakes failed");
        exit(1);
    }
    lat.sort_unstable();
    let ok = lat.len();
    let median = pct(&lat, 0.5);
    let p95 = pct(&lat, 0.95);
    let (mn, mx) = (lat[0] as f64, lat[ok - 1] as f64);
    let mean = lat.iter().map(|&x| x as f64).sum::<f64>() / ok as f64;
    let ss: f64 = lat.iter().map(|&x| (x as f64 - mean).powi(2)).sum();
    let stddev = if ok > 1 {
        (ss / (ok - 1) as f64).sqrt()
    } else {
        0.0
    };
    let hs_per_sec = if median > 0.0 { 1e9 / median } else { 0.0 };

    let mut row = String::new();
    write!(
        row,
        "{{\"label\":\"{}\",\"group\":\"{}\",\"sig_alg\":\"{}\",\"phase\":\"{}\",\
         \"implementation\":\"rustls-awslc\",\"unstable_features\":{},\"enabled\":true,\
         \"have_oqs_provider\":false,",
        cell.label, cell.group, cell.sig_alg, cell.phase, cell.unstable
    )
    .unwrap();
    write!(row, "\"connections\":{connections},\"succeeded\":{ok},").unwrap();
    write!(
        row,
        "\"handshake_latency_ns\":{{\"median\":{median:.1},\"p95\":{p95:.1},\"min\":{mn:.1},\
         \"max\":{mx:.1},\"mean\":{mean:.1},\"stddev\":{stddev:.1}}},"
    )
    .unwrap();
    write!(row, "\"handshakes_per_sec\":{hs_per_sec:.1},").unwrap();
    write!(
        row,
        "\"bytes_on_wire\":{{\"client_to_server\":{c2s_last},\"server_to_client\":{s2c_last},\
         \"total\":{}}},",
        c2s_last + s2c_last
    )
    .unwrap();
    write!(
        row,
        "\"client_hello_bytes\":{ch_last},\"client_hello_fragmented\":{},\"mss_assumed\":{TYPICAL_MSS}}}",
        ch_last > TYPICAL_MSS
    )
    .unwrap();
    println!("{row}");
}
