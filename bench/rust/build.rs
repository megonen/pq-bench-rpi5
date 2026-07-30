// Capture build-time provenance so the binary can emit it with --provenance:
// the Rust-side equivalent of the LIBOQS_OPT_DEFINES we record for C.
use std::env;
use std::process::Command;

fn main() {
    let set = |k: &str, v: &str| println!("cargo:rustc-env={k}={v}");

    set("PQB_TARGET", &env::var("TARGET").unwrap_or_default());
    set("PQB_PROFILE", &env::var("PROFILE").unwrap_or_default());
    set("PQB_OPT_LEVEL", &env::var("OPT_LEVEL").unwrap_or_default());
    set(
        "PQB_TARGET_FEATURES",
        &env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default(),
    );
    // RUSTFLAGS as cargo actually applied them (0x1f-separated encoding).
    let rustflags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .replace('\u{1f}', " ");
    set("PQB_RUSTFLAGS", &rustflags);

    // rustc version string (the same compiler cargo is driving).
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let ver = Command::new(&rustc)
        .arg("-V")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    set("PQB_RUSTC_VERSION", &ver);

    // Resolved versions of the measured crates, from the committed Cargo.lock.
    let lock = std::fs::read_to_string(
        std::path::Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.lock"),
    )
    .unwrap_or_default();
    for want in ["ml-kem", "ml-dsa", "slh-dsa", "x25519-dalek", "ed25519-dalek"] {
        let mut version = String::from("unknown");
        let mut in_pkg = false;
        for line in lock.lines() {
            let line = line.trim();
            if line == "[[package]]" {
                in_pkg = false;
            } else if line == format!("name = \"{want}\"") {
                in_pkg = true;
            } else if in_pkg && line.starts_with("version = ") {
                version = line
                    .trim_start_matches("version = ")
                    .trim_matches('"')
                    .to_string();
                break;
            }
        }
        set(
            &format!("PQB_CRATE_{}", want.replace('-', "_").to_uppercase()),
            &version,
        );
    }
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
}
