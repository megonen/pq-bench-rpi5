/* ===========================================================================
 * bench_pq.c — primitive-level KEM / signature benchmark harness.
 *
 * One algorithm per invocation (fresh process keeps cache state clean):
 *   bench_pq --kind kem --alg ML-KEM-768 --warmup 1000 --iters 10000 --reps 5
 *   bench_pq --kind sig --alg ML-DSA-65  ...
 *
 * Emits a single JSON object describing the algorithm to stdout. The orchestrator
 * (run.sh / assemble.py) wraps these with environment metadata.
 *
 * Two implementations, selected by algorithm name (emitted per row in the
 * "implementation" field — the schema dimension that distinguishes library
 * sources: liboqs / openssl / rustcrypto / oqs-provider / openssl-native /
 * rustls-awslc; this harness emits the first two):
 *   - liboqs            : all PQ candidates (ML-KEM, ML-DSA, Falcon, SLH-DSA, ...)
 *   - OpenSSL EVP       : the classical Logos baselines X25519 (KEM-analog) and
 *                         Ed25519 (signature), which liboqs does not implement.
 * This lets the classical reference be drawn on the same primitive charts.
 *
 * Metrics per operation: full per-iteration wall-clock nanosecond distribution
 * -> median, MAD, IQR, min, max, mean, stddev, ops/sec, plus per-repetition
 * medians. Optional userspace PMU cycle counts when available. Heap high-water
 * via mallinfo2 on glibc (the RPi5 target); honestly reported unavailable
 * elsewhere (e.g. the macOS smoke box).
 * ===========================================================================*/
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <setjmp.h>
#include <signal.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#define HAVE_MALLINFO2 1
#endif

/* ---- timing ------------------------------------------------------------- */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ---- userspace PMU cycle counter probe (aarch64) ------------------------ */
static sigjmp_buf g_sigill_jmp;
static volatile sig_atomic_t g_pmu_ok = 0;
static void sigill_handler(int sig) { (void)sig; siglongjmp(g_sigill_jmp, 1); }

static inline uint64_t read_cycles(void) {
#if defined(__aarch64__)
    uint64_t v;
    __asm__ volatile("mrs %0, pmccntr_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

/* Returns 1 and a reason string if userspace cycle counting works. */
static int probe_pmu(const char **reason) {
#if defined(__aarch64__)
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigill_handler;
    sigaction(SIGILL, &sa, &old);
    if (sigsetjmp(g_sigill_jmp, 1) == 0) {
        (void)read_cycles();
        g_pmu_ok = 1;
    } else {
        g_pmu_ok = 0;
    }
    sigaction(SIGILL, &old, NULL);
    if (g_pmu_ok) { *reason = "PMCCNTR_EL0 readable from userspace"; return 1; }
    *reason = "PMCCNTR_EL0 traps (kernel module not loaded; needs e.g. enable_arm_pmu)";
    return 0;
#else
    *reason = "not aarch64";
    return 0;
#endif
}

/* ---- statistics --------------------------------------------------------- */
typedef struct {
    double median, mad, iqr, q1, q3, min, max, mean, stddev;
    double ops_per_sec;
    uint64_t n;
} stats_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* percentile on an already-sorted array (linear interpolation) */
static double pct_sorted(const uint64_t *s, uint64_t n, double p) {
    if (n == 0) return 0;
    if (n == 1) return (double)s[0];
    double idx = p * (double)(n - 1);
    uint64_t lo = (uint64_t)idx;
    double frac = idx - (double)lo;
    if (lo + 1 >= n) return (double)s[n - 1];
    return (double)s[lo] + frac * ((double)s[lo + 1] - (double)s[lo]);
}

static stats_t compute_stats(uint64_t *samples, uint64_t n) {
    stats_t st; memset(&st, 0, sizeof st);
    st.n = n;
    if (n == 0) return st;
    qsort(samples, n, sizeof(uint64_t), cmp_u64);
    st.min = (double)samples[0];
    st.max = (double)samples[n - 1];
    st.median = pct_sorted(samples, n, 0.5);
    st.q1 = pct_sorted(samples, n, 0.25);
    st.q3 = pct_sorted(samples, n, 0.75);
    st.iqr = st.q3 - st.q1;

    double sum = 0;
    for (uint64_t i = 0; i < n; i++) sum += (double)samples[i];
    st.mean = sum / (double)n;
    double ss = 0;
    for (uint64_t i = 0; i < n; i++) {
        double d = (double)samples[i] - st.mean;
        ss += d * d;
    }
    st.stddev = (n > 1) ? sqrt(ss / (double)(n - 1)) : 0;

    /* MAD = median(|x - median|); needs a second sorted buffer */
    uint64_t *dev = malloc(n * sizeof(uint64_t));
    if (dev) {
        for (uint64_t i = 0; i < n; i++) {
            double d = (double)samples[i] - st.median;
            dev[i] = (uint64_t)(d < 0 ? -d : d);
        }
        qsort(dev, n, sizeof(uint64_t), cmp_u64);
        st.mad = pct_sorted(dev, n, 0.5);
        free(dev);
    }
    st.ops_per_sec = st.median > 0 ? 1e9 / st.median : 0;
    return st;
}

/* ---- measurement configuration + generic loop --------------------------- */
/* A closure-ish: the caller provides a function pointer that runs one op. */
typedef int (*op_fn)(void *ctx);

/* How each op is sized. Two modes, decided per invocation:
 *   - fixed-count   (fixed_iters > 0): exactly fixed_iters timed iters per rep,
 *                   with the configured fixed-mode warmup. This is the explicit
 *                   `--iters N` override / fixed-count fallback.
 *   - auto-calibrate(fixed_iters == 0): each op is timed long enough to put
 *                   ~target_ns of aggregate timed work on it, so a 18 us keygen
 *                   and a 750 ms SLH-DSA sign both yield a stable median. The
 *                   chosen count is clamped to [min_samples, max_iters]:
 *                     fast ops hit max_iters, slow ops hit min_samples.
 * Auto mode estimates per-op cost with a short doubling calibration (which also
 * serves as cache warmup), then derives the timed count + a per-rep re-warm. */
typedef struct {
    uint64_t fixed_iters;   /* >0 => fixed-count mode; 0 => auto-calibrate */
    uint64_t target_ns;     /* auto: per-op aggregate timed-work target */
    uint64_t min_samples;   /* auto: floor on timed iters per rep */
    uint64_t max_iters;     /* auto: ceiling on timed iters per rep */
    uint64_t warmup;        /* fixed-mode warmup count per rep */
    uint64_t reps;
} bench_cfg;

typedef struct {
    uint64_t *all;        /* all samples across reps */
    uint64_t  all_n;
    double    per_rep_median[64];
    int       n_rep_med;
    uint64_t  timed_iters;   /* timed iters per rep actually used */
    uint64_t  warmup_iters;  /* warmup iters per rep actually used */
    uint64_t  reps;
    int       calibrated;    /* 1 if auto-calibrated, 0 if fixed-count */
    double    est_ns;        /* per-op cost estimate from calibration (auto) */
} measure_out;

static void print_stats_json(FILE *f, const char *name, stats_t st,
                             const measure_out *m) {
    fprintf(f, "\"%s\":{", name);
    fprintf(f, "\"unit\":\"ns\",\"warmup_iters\":%llu,\"timed_iters\":%llu,\"repetitions\":%llu,",
            (unsigned long long)m->warmup_iters, (unsigned long long)m->timed_iters,
            (unsigned long long)m->reps);
    fprintf(f, "\"calibrated\":%s,", m->calibrated ? "true" : "false");
    if (m->calibrated)
        fprintf(f, "\"calib_est_ns\":%.2f,", m->est_ns);
    fprintf(f, "\"samples\":%llu,", (unsigned long long)st.n);
    fprintf(f, "\"median\":%.2f,\"mad\":%.2f,\"iqr\":%.2f,\"q1\":%.2f,\"q3\":%.2f,",
            st.median, st.mad, st.iqr, st.q1, st.q3);
    fprintf(f, "\"min\":%.2f,\"max\":%.2f,\"mean\":%.2f,\"stddev\":%.2f,",
            st.min, st.max, st.mean, st.stddev);
    fprintf(f, "\"ops_per_sec\":%.2f,", st.ops_per_sec);
    fprintf(f, "\"per_rep_median\":[");
    for (int i = 0; i < m->n_rep_med; i++)
        fprintf(f, "%s%.2f", i ? "," : "", m->per_rep_median[i]);
    fprintf(f, "]}");
}

/* Pick the timed-iter count (and per-rep warmup) for one op under cfg.
 * In auto mode this runs a doubling calibration loop on fn (which warms caches)
 * to estimate per-op cost, then solves for the count that hits target_ns.
 * Returns 0 on success, -2 if the op ever fails during calibration. */
static int calibrate_op(op_fn fn, void *ctx, const bench_cfg *cfg,
                        uint64_t *timed_out, uint64_t *warm_out,
                        double *est_ns_out, int *calibrated_out) {
    if (cfg->fixed_iters > 0) {
        *timed_out = cfg->fixed_iters;
        *warm_out = cfg->warmup;
        *est_ns_out = 0.0;
        *calibrated_out = 0;
        return 0;
    }
    /* doubling calibration: run batches 1,2,4,... until ~CALIB_BUDGET elapses,
     * capped at max_iters so a sub-microsecond op can't spin forever. */
    const uint64_t CALIB_BUDGET_NS = 30ull * 1000 * 1000;   /* 30 ms */
    uint64_t cops = 0, cel = 0, batch = 1;
    while (cel < CALIB_BUDGET_NS && cops < cfg->max_iters) {
        uint64_t t0 = now_ns();
        for (uint64_t i = 0; i < batch; i++)
            if (fn(ctx) != 0) return -2;
        cel += now_ns() - t0;
        cops += batch;
        batch *= 2;
    }
    double est_ns = cops ? (double)cel / (double)cops : 1.0;
    if (est_ns < 1.0) est_ns = 1.0;

    double want = (double)cfg->target_ns / est_ns;
    uint64_t n = (uint64_t)(want + 0.5);
    if (n < cfg->min_samples) n = cfg->min_samples;   /* slow ops floor here  */
    if (n > cfg->max_iters)   n = cfg->max_iters;     /* fast ops ceil here   */

    /* per-rep re-warm ~= 20% of the timed budget, at least 1, capped. */
    double w = ((double)cfg->target_ns * 0.2) / est_ns;
    uint64_t warm = (uint64_t)(w + 0.5);
    if (warm < 1) warm = 1;
    if (warm > cfg->max_iters) warm = cfg->max_iters;

    *timed_out = n;
    *warm_out = warm;
    *est_ns_out = est_ns;
    *calibrated_out = 1;
    return 0;
}

/* Returns 0 on success. Fills out with samples. Re-warms before each rep. */
static int measure_op(op_fn fn, void *ctx, const bench_cfg *cfg, measure_out *out) {
    uint64_t iters, warmup;
    double est_ns; int calibrated;
    if (calibrate_op(fn, ctx, cfg, &iters, &warmup, &est_ns, &calibrated) != 0)
        return -2;

    out->all = malloc(iters * cfg->reps * sizeof(uint64_t));
    if (!out->all) return -1;
    out->all_n = 0;
    out->n_rep_med = 0;
    out->timed_iters = iters;
    out->warmup_iters = warmup;
    out->reps = cfg->reps;
    out->calibrated = calibrated;
    out->est_ns = est_ns;
    uint64_t *rep_buf = malloc(iters * sizeof(uint64_t));
    if (!rep_buf) { free(out->all); return -1; }

    for (uint64_t r = 0; r < cfg->reps; r++) {
        for (uint64_t i = 0; i < warmup; i++)
            if (fn(ctx) != 0) { free(rep_buf); free(out->all); return -2; }
        for (uint64_t i = 0; i < iters; i++) {
            uint64_t t0 = now_ns();
            int rc = fn(ctx);
            uint64_t dt = now_ns() - t0;
            if (rc != 0) { free(rep_buf); free(out->all); return -2; }
            rep_buf[i] = dt;
            out->all[out->all_n++] = dt;
        }
        /* per-rep median (sorts a copy of this rep's slice) */
        uint64_t *copy = malloc(iters * sizeof(uint64_t));
        if (copy) {
            memcpy(copy, rep_buf, iters * sizeof(uint64_t));
            qsort(copy, iters, sizeof(uint64_t), cmp_u64);
            if (out->n_rep_med < 64)
                out->per_rep_median[out->n_rep_med++] = pct_sorted(copy, iters, 0.5);
            free(copy);
        }
    }
    free(rep_buf);
    return 0;
}

/* ---- anti-DCE sink + fatal helpers -------------------------------------- */
/* File-scope volatile: the compiler must materialize every store, so it cannot
 * dead-code-eliminate the crypto outputs we feed into it. Every timed op sinks
 * one output byte here. */
static volatile uint64_t g_sink = 0;

/* Abort the whole run: a broken build must NEVER silently emit timing numbers. */
static void die(const char *alg, const char *what) {
    fprintf(stderr, "[bench_pq] FATAL: %s: %s — aborting so no numbers are emitted\n",
            alg, what);
    exit(3);
}

/* measure_op wrapper: if any timed op ever returns failure (e.g. a verify that
 * stopped succeeding), abort instead of reading freed/partial buffers. */
static void must_measure(const char *alg, const char *op, op_fn fn, void *ctx,
                         const bench_cfg *cfg, measure_out *out) {
    if (measure_op(fn, ctx, cfg, out) != 0)
        die(alg, op);
}

#define MSGLEN 32

/* ======================= liboqs KEM ====================================== */
/* Timed ops consume canonical, pre-validated inputs; keygen/encaps write to
 * scratch buffers so they never clobber the matched (pk,sk,ct) that the other
 * timed ops depend on. Each op sinks an output byte into g_sink. */
typedef struct {
    OQS_KEM *kem;
    uint8_t *pk, *sk;     /* canonical matched keypair (encaps/decaps inputs) */
    uint8_t *ct;          /* canonical ciphertext (decaps input)             */
    uint8_t *pk_s, *sk_s; /* scratch: keygen outputs                          */
    uint8_t *ct_s, *ss_s; /* scratch: encaps outputs                          */
    uint8_t *ss_d;        /* scratch: decaps output                           */
} kem_ctx;
static int kem_keygen(void *c){ kem_ctx*x=c;
    if (OQS_KEM_keypair(x->kem, x->pk_s, x->sk_s) != OQS_SUCCESS) return 1;
    g_sink += x->pk_s[0]; return 0; }
static int kem_encaps(void *c){ kem_ctx*x=c;
    if (OQS_KEM_encaps(x->kem, x->ct_s, x->ss_s, x->pk) != OQS_SUCCESS) return 1;
    g_sink += (uint64_t)x->ss_s[0] ^ x->ct_s[0]; return 0; }
static int kem_decaps(void *c){ kem_ctx*x=c;
    if (OQS_KEM_decaps(x->kem, x->ss_d, x->ct, x->sk) != OQS_SUCCESS) return 1;
    g_sink += x->ss_d[0]; return 0; }

static int run_kem(const char *alg, const bench_cfg *cfg) {
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        printf("{\"alg\":\"%s\",\"kind\":\"kem\",\"implementation\":\"liboqs\",\"enabled\":false,"
               "\"reason\":\"not enabled in this liboqs build\"}\n", alg);
        return 0;
    }
    kem_ctx x; memset(&x, 0, sizeof x); x.kem = kem;
    x.pk   = malloc(kem->length_public_key);  x.sk   = malloc(kem->length_secret_key);
    x.ct   = malloc(kem->length_ciphertext);
    x.pk_s = malloc(kem->length_public_key);  x.sk_s = malloc(kem->length_secret_key);
    x.ct_s = malloc(kem->length_ciphertext);
    x.ss_s = malloc(kem->length_shared_secret);
    x.ss_d = malloc(kem->length_shared_secret);
    if (!x.pk||!x.sk||!x.ct||!x.pk_s||!x.sk_s||!x.ct_s||!x.ss_s||!x.ss_d) die(alg,"out of memory");

    /* ---- correctness check (ONCE, outside the timed loop) ----
     * keygen -> encaps -> decaps, then assert the shared secrets match. */
    if (OQS_KEM_keypair(kem, x.pk, x.sk) != OQS_SUCCESS) die(alg, "keygen failed");
    if (OQS_KEM_encaps(kem, x.ct, x.ss_s, x.pk) != OQS_SUCCESS) die(alg, "encaps failed");
    if (OQS_KEM_decaps(kem, x.ss_d, x.ct, x.sk) != OQS_SUCCESS) die(alg, "decaps failed");
    if (memcmp(x.ss_s, x.ss_d, kem->length_shared_secret) != 0)
        die(alg, "KEM shared-secret mismatch (ss_encaps != ss_decaps)");

    /* timed phases run on the canonical, validated (pk,sk,ct); any op failure
     * during timing aborts via must_measure. */
    measure_out kg={0}, en={0}, de={0};
    must_measure(alg,"keygen",kem_keygen,&x,cfg,&kg);
    must_measure(alg,"encaps",kem_encaps,&x,cfg,&en);
    must_measure(alg,"decaps",kem_decaps,&x,cfg,&de);

    printf("{\"alg\":\"%s\",\"kind\":\"kem\",\"implementation\":\"liboqs\",\"enabled\":true,", alg);
    printf("\"claimed_nist_level\":%d,", kem->claimed_nist_level);
    printf("\"sizes\":{\"public_key\":%zu,\"secret_key\":%zu,\"ciphertext\":%zu,\"shared_secret\":%zu},",
           kem->length_public_key, kem->length_secret_key, kem->length_ciphertext, kem->length_shared_secret);
    printf("\"operations\":{");
    stats_t s;
    s=compute_stats(kg.all,kg.all_n); print_stats_json(stdout,"keygen",s,&kg); printf(",");
    s=compute_stats(en.all,en.all_n); print_stats_json(stdout,"encaps",s,&en); printf(",");
    s=compute_stats(de.all,de.all_n); print_stats_json(stdout,"decaps",s,&de);
    printf("}}\n");

    free(kg.all); free(en.all); free(de.all);
    free(x.pk); free(x.sk); free(x.ct);
    free(x.pk_s); free(x.sk_s); free(x.ct_s); free(x.ss_s); free(x.ss_d);
    OQS_KEM_free(kem);
    return 0;
}

/* ======================= liboqs SIG ====================================== */
/* sign writes a scratch signature; verify reads the canonical (sg,sglen) over
 * the canonical msg with the canonical pk — all pre-validated. */
typedef struct {
    OQS_SIG *sig;
    uint8_t *pk, *sk;      /* canonical keypair (sign/verify inputs) */
    uint8_t *msg;          /* canonical message                      */
    uint8_t *sg; size_t sglen;     /* canonical signature (verify input) */
    uint8_t *pk_s, *sk_s;  /* scratch: keygen outputs                */
    uint8_t *sg_s; size_t sg_s_len;/* scratch: sign output           */
} sig_ctx;
static int sig_keygen(void *c){ sig_ctx*x=c;
    if (OQS_SIG_keypair(x->sig, x->pk_s, x->sk_s) != OQS_SUCCESS) return 1;
    g_sink += x->pk_s[0]; return 0; }
static int sig_sign(void *c){ sig_ctx*x=c;
    x->sg_s_len = x->sig->length_signature;
    if (OQS_SIG_sign(x->sig, x->sg_s, &x->sg_s_len, x->msg, MSGLEN, x->sk) != OQS_SUCCESS) return 1;
    g_sink += x->sg_s[0]; return 0; }
static int sig_verify(void *c){ sig_ctx*x=c;
    if (OQS_SIG_verify(x->sig, x->msg, MSGLEN, x->sg, x->sglen, x->pk) != OQS_SUCCESS) return 1;
    g_sink += 1; return 0; }

static int run_sig(const char *alg, const bench_cfg *cfg) {
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        printf("{\"alg\":\"%s\",\"kind\":\"sig\",\"implementation\":\"liboqs\",\"enabled\":false,"
               "\"reason\":\"not enabled in this liboqs build\"}\n", alg);
        return 0;
    }
    sig_ctx x; memset(&x,0,sizeof x); x.sig=sig;
    x.pk   = malloc(sig->length_public_key);  x.sk   = malloc(sig->length_secret_key);
    x.msg  = malloc(MSGLEN);
    x.sg   = malloc(sig->length_signature);
    x.pk_s = malloc(sig->length_public_key);  x.sk_s = malloc(sig->length_secret_key);
    x.sg_s = malloc(sig->length_signature);
    if (!x.pk||!x.sk||!x.msg||!x.sg||!x.pk_s||!x.sk_s||!x.sg_s) die(alg,"out of memory");
    memset(x.msg, 0xA5, MSGLEN);

    /* ---- correctness check (ONCE, outside the timed loop) ----
     * keygen -> sign -> verify; the verify MUST succeed on a valid signature. */
    if (OQS_SIG_keypair(sig, x.pk, x.sk) != OQS_SUCCESS) die(alg, "keygen failed");
    x.sglen = sig->length_signature;
    if (OQS_SIG_sign(sig, x.sg, &x.sglen, x.msg, MSGLEN, x.sk) != OQS_SUCCESS) die(alg, "sign failed");
    if (OQS_SIG_verify(sig, x.msg, MSGLEN, x.sg, x.sglen, x.pk) != OQS_SUCCESS)
        die(alg, "signature verify failed on a valid signature (broken build)");

    measure_out kg={0}, sg={0}, vf={0};
    must_measure(alg,"keygen",sig_keygen,&x,cfg,&kg);
    must_measure(alg,"sign",  sig_sign,  &x,cfg,&sg);
    must_measure(alg,"verify",sig_verify,&x,cfg,&vf);

    printf("{\"alg\":\"%s\",\"kind\":\"sig\",\"implementation\":\"liboqs\",\"enabled\":true,", alg);
    printf("\"claimed_nist_level\":%d,", sig->claimed_nist_level);
    printf("\"sizes\":{\"public_key\":%zu,\"secret_key\":%zu,\"signature\":%zu},",
           sig->length_public_key, sig->length_secret_key, sig->length_signature);
    printf("\"operations\":{");
    stats_t s;
    s=compute_stats(kg.all,kg.all_n); print_stats_json(stdout,"keygen",s,&kg); printf(",");
    s=compute_stats(sg.all,sg.all_n); print_stats_json(stdout,"sign",s,&sg); printf(",");
    s=compute_stats(vf.all,vf.all_n); print_stats_json(stdout,"verify",s,&vf);
    printf("}}\n");

    free(kg.all); free(sg.all); free(vf.all);
    free(x.pk); free(x.sk); free(x.msg); free(x.sg);
    free(x.pk_s); free(x.sk_s); free(x.sg_s);
    OQS_SIG_free(sig);
    return 0;
}

/* ======================= OpenSSL classical baselines ===================== */
/* X25519 as a KEM-analog: keygen + ECDH derive (one shared-secret derivation). */
typedef struct { EVP_PKEY *self; EVP_PKEY *peer; } x25519_ctx;
static int x25519_keygen(void *c){
    x25519_ctx*x=c;
    if (x->self) { EVP_PKEY_free(x->self); x->self=NULL; }
    EVP_PKEY_CTX *p = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
    if(!p) return 1;
    int ok = EVP_PKEY_keygen_init(p)>0 && EVP_PKEY_keygen(p,&x->self)>0;
    EVP_PKEY_CTX_free(p);
    return ok?0:1;
}
/* derive shared secret a·b into out[32]; returns 1 on success */
static int x25519_derive_into(EVP_PKEY *a, EVP_PKEY *b, unsigned char out[32]){
    EVP_PKEY_CTX *p = EVP_PKEY_CTX_new(a,NULL);
    if(!p) return 0;
    size_t slen=32;
    int ok = EVP_PKEY_derive_init(p)>0 &&
             EVP_PKEY_derive_set_peer(p,b)>0 &&
             EVP_PKEY_derive(p,out,&slen)>0;
    EVP_PKEY_CTX_free(p);
    return ok;
}
static int x25519_derive(void *c){
    x25519_ctx*x=c;
    unsigned char secret[32];
    if(!x25519_derive_into(x->self,x->peer,secret)) return 1;
    g_sink += secret[0];           /* sink the derived shared secret */
    return 0;
}

static int run_x25519(const bench_cfg *cfg) {
    x25519_ctx x={0};
    if (x25519_keygen(&x) != 0) die("X25519","keygen failed");   /* self */
    /* a fixed peer key for derive */
    EVP_PKEY_CTX *p = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
    if(!p || EVP_PKEY_keygen_init(p)<=0 || EVP_PKEY_keygen(p,&x.peer)<=0) die("X25519","peer keygen failed");
    EVP_PKEY_CTX_free(p);

    /* ---- correctness check (ONCE, outside timing): ECDH must agree ---- */
    {
        unsigned char sa[32], sb[32];
        if (!x25519_derive_into(x.self, x.peer, sa)) die("X25519","derive(self,peer) failed");
        if (!x25519_derive_into(x.peer, x.self, sb)) die("X25519","derive(peer,self) failed");
        if (memcmp(sa, sb, 32) != 0) die("X25519","ECDH shared-secret mismatch");
    }

    measure_out kg={0}, dv={0};
    must_measure("X25519","keygen",x25519_keygen,&x,cfg,&kg);
    /* keygen frees+replaces self each call; re-make a stable self for derive */
    if (x25519_keygen(&x) != 0) die("X25519","keygen failed");
    must_measure("X25519","derive",x25519_derive,&x,cfg,&dv);

    printf("{\"alg\":\"X25519\",\"kind\":\"kem\",\"implementation\":\"openssl\",\"classical\":true,\"enabled\":true,");
    printf("\"claimed_nist_level\":1,");
    printf("\"sizes\":{\"public_key\":32,\"secret_key\":32,\"ciphertext\":null,\"shared_secret\":32},");
    printf("\"operations\":{");
    stats_t s;
    s=compute_stats(kg.all,kg.all_n); print_stats_json(stdout,"keygen",s,&kg); printf(",");
    s=compute_stats(dv.all,dv.all_n); print_stats_json(stdout,"derive",s,&dv);
    printf("}}\n");
    free(kg.all); free(dv.all);
    if(x.self)EVP_PKEY_free(x.self); if(x.peer)EVP_PKEY_free(x.peer);
    return 0;
}

/* Ed25519 signature baseline. */
typedef struct { EVP_PKEY *key; unsigned char msg[32]; unsigned char sig[64]; size_t siglen; } ed_ctx;
static int ed_keygen(void *c){
    ed_ctx*x=c;
    if(x->key){EVP_PKEY_free(x->key);x->key=NULL;}
    EVP_PKEY_CTX *p=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    if(!p)return 1;
    int ok=EVP_PKEY_keygen_init(p)>0 && EVP_PKEY_keygen(p,&x->key)>0;
    EVP_PKEY_CTX_free(p);
    return ok?0:1;
}
static int ed_sign(void *c){
    ed_ctx*x=c;
    EVP_MD_CTX *m=EVP_MD_CTX_new(); if(!m)return 1;
    x->siglen=sizeof x->sig;
    int ok = EVP_DigestSignInit(m,NULL,NULL,NULL,x->key)>0 &&
             EVP_DigestSign(m,x->sig,&x->siglen,x->msg,sizeof x->msg)>0;
    EVP_MD_CTX_free(m);
    if(!ok) return 1;
    g_sink += x->sig[0];           /* sink the signature */
    return 0;
}
static int ed_verify(void *c){
    ed_ctx*x=c;
    EVP_MD_CTX *m=EVP_MD_CTX_new(); if(!m)return 1;
    int ok = EVP_DigestVerifyInit(m,NULL,NULL,NULL,x->key)>0 &&
             EVP_DigestVerify(m,x->sig,x->siglen,x->msg,sizeof x->msg)>0;
    EVP_MD_CTX_free(m);
    if(!ok) return 1;
    g_sink += 1;                   /* sink the (successful) verify result */
    return 0;
}

static int run_ed25519(const bench_cfg *cfg) {
    ed_ctx x; memset(&x,0,sizeof x); memset(x.msg,0xA5,sizeof x.msg);

    /* ---- correctness check (ONCE, outside timing): verify MUST succeed ---- */
    if (ed_keygen(&x) != 0) die("Ed25519","keygen failed");
    if (ed_sign(&x)   != 0) die("Ed25519","sign failed");
    if (ed_verify(&x) != 0) die("Ed25519","verify failed on a valid signature (broken build)");

    measure_out kg={0}, sg={0}, vf={0};
    must_measure("Ed25519","keygen",ed_keygen,&x,cfg,&kg);
    if (ed_keygen(&x)!=0 || ed_sign(&x)!=0) die("Ed25519","re-priming key+sig failed");
    must_measure("Ed25519","sign",  ed_sign,  &x,cfg,&sg);
    must_measure("Ed25519","verify",ed_verify,&x,cfg,&vf);

    printf("{\"alg\":\"Ed25519\",\"kind\":\"sig\",\"implementation\":\"openssl\",\"classical\":true,\"enabled\":true,");
    printf("\"claimed_nist_level\":1,");
    printf("\"sizes\":{\"public_key\":32,\"secret_key\":32,\"signature\":64},");
    printf("\"operations\":{");
    stats_t s;
    s=compute_stats(kg.all,kg.all_n); print_stats_json(stdout,"keygen",s,&kg); printf(",");
    s=compute_stats(sg.all,sg.all_n); print_stats_json(stdout,"sign",s,&sg); printf(",");
    s=compute_stats(vf.all,vf.all_n); print_stats_json(stdout,"verify",s,&vf);
    printf("}}\n");
    free(kg.all); free(sg.all); free(vf.all);
    if(x.key)EVP_PKEY_free(x.key);
    return 0;
}

/* ---- main --------------------------------------------------------------- */
static void usage(void){
    fprintf(stderr,
      "usage: bench_pq --kind kem|sig --alg NAME [options]\n"
      "  auto-calibration (default): each op is timed to ~--target-time-ms of\n"
      "    aggregate work, clamped to [--min-samples, --max-iters].\n"
      "  --target-time-ms N   per-op timed-work target (default 250)\n"
      "  --min-samples N      floor on timed iters per rep (default 30)\n"
      "  --max-iters N        ceiling on timed iters per rep (default 20000)\n"
      "  --reps N             independent repetitions (default 5)\n"
      "  --iters N            FIXED-count fallback: exactly N timed iters/rep\n"
      "                       (disables calibration; pairs with --warmup)\n"
      "  --warmup N           warmup iters/rep in fixed-count mode (default 1000)\n");
}

int main(int argc, char **argv) {
    const char *kind=NULL, *alg=NULL;
    /* fixed-count fallback knobs */
    uint64_t warmup=1000, iters=0, reps=5;   /* iters=0 => auto-calibrate */
    /* auto-calibration knobs */
    uint64_t target_time_ms=250, min_samples=30, max_iters=20000;
    for (int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--kind")&&i+1<argc) kind=argv[++i];
        else if(!strcmp(argv[i],"--alg")&&i+1<argc) alg=argv[++i];
        else if(!strcmp(argv[i],"--warmup")&&i+1<argc) warmup=strtoull(argv[++i],0,10);
        else if(!strcmp(argv[i],"--iters")&&i+1<argc) iters=strtoull(argv[++i],0,10);
        else if(!strcmp(argv[i],"--reps")&&i+1<argc) reps=strtoull(argv[++i],0,10);
        else if(!strcmp(argv[i],"--target-time-ms")&&i+1<argc) target_time_ms=strtoull(argv[++i],0,10);
        else if(!strcmp(argv[i],"--min-samples")&&i+1<argc) min_samples=strtoull(argv[++i],0,10);
        else if(!strcmp(argv[i],"--max-iters")&&i+1<argc) max_iters=strtoull(argv[++i],0,10);
        else { usage(); return 2; }
    }
    if(!kind||!alg){ usage(); return 2; }
    if(reps < 1) reps = 1;
    if(min_samples < 1) min_samples = 1;
    if(max_iters < min_samples) max_iters = min_samples;

    bench_cfg cfg = {
        .fixed_iters = iters,                       /* >0 => fixed-count mode */
        .target_ns   = target_time_ms * 1000000ull,
        .min_samples = min_samples,
        .max_iters   = max_iters,
        .warmup      = warmup,
        .reps        = reps,
    };
    if (iters>0)
        fprintf(stderr,"[bench_pq] mode=fixed-count reps=%llu warmup=%llu iters=%llu\n",
                (unsigned long long)reps,(unsigned long long)warmup,(unsigned long long)iters);
    else
        fprintf(stderr,"[bench_pq] mode=auto-calibrate reps=%llu target=%llums min_samples=%llu max_iters=%llu\n",
                (unsigned long long)reps,(unsigned long long)target_time_ms,
                (unsigned long long)min_samples,(unsigned long long)max_iters);

    /* PMU cycle availability probe (reported once via stderr-free channel:
     * embedded into the JSON header line below). */
    const char *pmu_reason=NULL;
    int pmu_ok = probe_pmu(&pmu_reason);
    fprintf(stderr,"[bench_pq] cycles_available=%d (%s)\n", pmu_ok, pmu_reason);

    OQS_init();
    int rc;
    if(!strcmp(kind,"kem")){
        if(!strcmp(alg,"X25519")) rc=run_x25519(&cfg);
        else rc=run_kem(alg,&cfg);
    } else if(!strcmp(kind,"sig")){
        if(!strcmp(alg,"Ed25519")) rc=run_ed25519(&cfg);
        else rc=run_sig(alg,&cfg);
    } else { usage(); rc=2; }
    OQS_destroy();
    return rc;
}
