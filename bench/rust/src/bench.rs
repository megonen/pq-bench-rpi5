//! Measurement engine — a deliberate, line-for-line replication of the timing,
//! auto-calibration and statistics logic in bench/kem_sig/bench_pq.c, so that
//! rustcrypto rows are methodologically comparable to liboqs rows. Any change
//! here must be mirrored there (and vice versa). C references cite bench_pq.c.

use std::process::exit;

/// bench_pq.c now_ns() (:44-48): clock_gettime(CLOCK_MONOTONIC). We call the
/// same clock via libc — std::time::Instant would use mach_absolute_time on
/// macOS, a different timebase than the C harness.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// bench_pq.c die() (:303-307): a broken build must NEVER silently emit
/// timing numbers. stderr + exit(3), no stdout.
pub fn die(alg: &str, what: &str) -> ! {
    eprintln!("[pqb-rust] FATAL: {alg}: {what} — aborting so no numbers are emitted");
    exit(3);
}

/// bench_pq.c bench_cfg (:163-170).
pub struct BenchCfg {
    pub fixed_iters: u64, // >0 => fixed-count mode; 0 => auto-calibrate
    pub target_ns: u64,
    pub min_samples: u64,
    pub max_iters: u64,
    pub warmup: u64,
    pub reps: u64,
}

/// bench_pq.c measure_out (:172-182).
pub struct MeasureOut {
    pub all: Vec<u64>,
    pub per_rep_median: Vec<f64>, // capped at 64, like the C array
    pub timed_iters: u64,
    pub warmup_iters: u64,
    pub reps: u64,
    pub calibrated: bool,
    pub est_ns: f64,
}

/// bench_pq.c pct_sorted() (:100-109): percentile with linear interpolation
/// on an already-sorted slice.
fn pct_sorted(s: &[u64], p: f64) -> f64 {
    let n = s.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return s[0] as f64;
    }
    let idx = p * (n - 1) as f64;
    let lo = idx as usize;
    let frac = idx - lo as f64;
    if lo + 1 >= n {
        return s[n - 1] as f64;
    }
    s[lo] as f64 + frac * (s[lo + 1] as f64 - s[lo] as f64)
}

/// bench_pq.c stats_t + compute_stats() (:89-146). Consumes the sample vec
/// (sorts in place, like the C qsort).
pub struct Stats {
    pub median: f64,
    pub mad: f64,
    pub iqr: f64,
    pub q1: f64,
    pub q3: f64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
    pub ops_per_sec: f64,
    pub n: u64,
}

pub fn compute_stats(samples: &mut Vec<u64>) -> Stats {
    let n = samples.len();
    if n == 0 {
        return Stats {
            median: 0.0,
            mad: 0.0,
            iqr: 0.0,
            q1: 0.0,
            q3: 0.0,
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            stddev: 0.0,
            ops_per_sec: 0.0,
            n: 0,
        };
    }
    samples.sort_unstable();
    let median = pct_sorted(samples, 0.5);
    let q1 = pct_sorted(samples, 0.25);
    let q3 = pct_sorted(samples, 0.75);
    let sum: f64 = samples.iter().map(|&x| x as f64).sum();
    let mean = sum / n as f64;
    let ss: f64 = samples
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum();
    let stddev = if n > 1 {
        (ss / (n - 1) as f64).sqrt()
    } else {
        0.0
    };
    // MAD = median(|x - median|). The C code truncates each deviation to
    // uint64_t before sorting (:134-142); replicate that cast exactly.
    let mut dev: Vec<u64> = samples
        .iter()
        .map(|&x| {
            let d = x as f64 - median;
            (if d < 0.0 { -d } else { d }) as u64
        })
        .collect();
    dev.sort_unstable();
    let mad = pct_sorted(&dev, 0.5);
    Stats {
        median,
        mad,
        iqr: q3 - q1,
        q1,
        q3,
        min: samples[0] as f64,
        max: samples[n - 1] as f64,
        mean,
        stddev,
        ops_per_sec: if median > 0.0 { 1e9 / median } else { 0.0 },
        n: n as u64,
    }
}

/// bench_pq.c calibrate_op() (:209-250): doubling calibration (which also
/// warms caches) -> per-op cost estimate -> timed count clamped to
/// [min_samples, max_iters], per-rep re-warm ~20% of the timed budget.
fn calibrate_op(
    f: &mut dyn FnMut() -> Result<(), ()>,
    cfg: &BenchCfg,
) -> Result<(u64, u64, f64, bool), ()> {
    if cfg.fixed_iters > 0 {
        return Ok((cfg.fixed_iters, cfg.warmup, 0.0, false));
    }
    const CALIB_BUDGET_NS: u64 = 30_000_000; // 30 ms, same as C (:221)
    let (mut cops, mut cel, mut batch) = (0u64, 0u64, 1u64);
    while cel < CALIB_BUDGET_NS && cops < cfg.max_iters {
        let t0 = now_ns();
        for _ in 0..batch {
            f()?;
        }
        cel += now_ns() - t0;
        cops += batch;
        batch *= 2;
    }
    let mut est_ns = if cops > 0 {
        cel as f64 / cops as f64
    } else {
        1.0
    };
    if est_ns < 1.0 {
        est_ns = 1.0;
    }
    let want = cfg.target_ns as f64 / est_ns;
    let mut n = (want + 0.5) as u64;
    n = n.clamp(cfg.min_samples, cfg.max_iters);
    let w = (cfg.target_ns as f64 * 0.2) / est_ns;
    let mut warm = (w + 0.5) as u64;
    if warm < 1 {
        warm = 1;
    }
    if warm > cfg.max_iters {
        warm = cfg.max_iters;
    }
    Ok((n, warm, est_ns, true))
}

/// bench_pq.c measure_op() (:253-294): per-rep re-warm, then each op timed
/// individually; per-rep medians recorded (up to 64), all samples pooled.
pub fn measure_op(f: &mut dyn FnMut() -> Result<(), ()>, cfg: &BenchCfg) -> Result<MeasureOut, ()> {
    let (iters, warmup, est_ns, calibrated) = calibrate_op(f, cfg)?;
    let mut out = MeasureOut {
        all: Vec::with_capacity((iters * cfg.reps) as usize),
        per_rep_median: Vec::new(),
        timed_iters: iters,
        warmup_iters: warmup,
        reps: cfg.reps,
        calibrated,
        est_ns,
    };
    let mut rep_buf: Vec<u64> = Vec::with_capacity(iters as usize);
    for _ in 0..cfg.reps {
        for _ in 0..warmup {
            f()?;
        }
        rep_buf.clear();
        for _ in 0..iters {
            let t0 = now_ns();
            let rc = f();
            let dt = now_ns() - t0;
            rc?;
            rep_buf.push(dt);
            out.all.push(dt);
        }
        let mut copy = rep_buf.clone();
        copy.sort_unstable();
        if out.per_rep_median.len() < 64 {
            out.per_rep_median.push(pct_sorted(&copy, 0.5));
        }
    }
    Ok(out)
}

/// measure_op wrapper mirroring must_measure() (:311-315).
pub fn must_measure(
    alg: &str,
    op: &str,
    f: &mut dyn FnMut() -> Result<(), ()>,
    cfg: &BenchCfg,
) -> MeasureOut {
    match measure_op(f, cfg) {
        Ok(m) => m,
        Err(()) => die(alg, op),
    }
}

/// bench_pq.c print_stats_json() (:184-203) — identical field set and
/// formatting (%.2f) so rows are diffable against liboqs rows.
pub fn stats_json(name: &str, st: &Stats, m: &MeasureOut) -> String {
    let mut s = format!("\"{name}\":{{");
    s += &format!(
        "\"unit\":\"ns\",\"warmup_iters\":{},\"timed_iters\":{},\"repetitions\":{},",
        m.warmup_iters, m.timed_iters, m.reps
    );
    s += &format!("\"calibrated\":{},", m.calibrated);
    if m.calibrated {
        s += &format!("\"calib_est_ns\":{:.2},", m.est_ns);
    }
    s += &format!("\"samples\":{},", st.n);
    s += &format!(
        "\"median\":{:.2},\"mad\":{:.2},\"iqr\":{:.2},\"q1\":{:.2},\"q3\":{:.2},",
        st.median, st.mad, st.iqr, st.q1, st.q3
    );
    s += &format!(
        "\"min\":{:.2},\"max\":{:.2},\"mean\":{:.2},\"stddev\":{:.2},",
        st.min, st.max, st.mean, st.stddev
    );
    s += &format!("\"ops_per_sec\":{:.2},", st.ops_per_sec);
    s += "\"per_rep_median\":[";
    for (i, v) in m.per_rep_median.iter().enumerate() {
        if i > 0 {
            s += ",";
        }
        s += &format!("{v:.2}");
    }
    s += "]}";
    s
}
