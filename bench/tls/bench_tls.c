/* ===========================================================================
 * bench_tls.c — TLS 1.3 handshake benchmark via the OpenSSL API.
 *
 * Performs full TLS 1.3 handshakes entirely in-process over a pair of memory
 * BIOs (no sockets, no CLI scraping). This gives:
 *   - clean per-handshake wall-clock latency (no socket/scheduler noise)
 *   - exact bytes-on-the-wire each direction
 *   - the precise ClientHello flight size (with a fragmentation note vs MSS)
 *   - real server-cert signature verification cost (client verifies the chain),
 *     which is the whole point of sweeping PQ signature algorithms.
 *
 *   bench_tls --group X25519MLKEM768 --ca ca.pem \
 *             --cert server.pem --key server.key --connections 1000 \
 *             --label "X25519MLKEM768+mldsa65" \
 *             --sig-alg mldsa65 --phase phase2 --implementation oqs-provider
 *
 * Emits one JSON object. The caller (run_tls.sh) supplies the row's schema
 * annotations verbatim: `phase` (baseline | phase0 | phase2 — the migration
 * framework), `implementation` (which TLS stack produced the number), and
 * `sig_alg` (the certificate signature algorithm, separate from the label so
 * downstream code never has to parse labels). PQ groups/sigs require
 * oqs-provider to be loadable (point OPENSSL_MODULES at its directory); if it
 * cannot load, we say so.
 * ===========================================================================*/
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define TYPICAL_MSS 1400   /* note fragmentation when ClientHello exceeds this */

static inline uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static double pct(const uint64_t *s, uint64_t n, double p) {
    if (!n) return 0; if (n == 1) return (double)s[0];
    double idx = p * (double)(n - 1); uint64_t lo = (uint64_t)idx; double f = idx - lo;
    if (lo + 1 >= n) return (double)s[n - 1];
    return (double)s[lo] + f * ((double)s[lo + 1] - (double)s[lo]);
}

/* OSSL_PROVIDER_do_all callback: flag any active provider whose name looks
 * like an OQS provider (native-mode assertion). */
static int check_no_oqs_provider(OSSL_PROVIDER *prov, void *cbdata) {
    const char *name = OSSL_PROVIDER_get0_name(prov);
    if (name && strstr(name, "oqs") != NULL)
        *(int *)cbdata = 1;
    return 1;
}

/* Shuttle all pending bytes from src's mem BIO into dst's mem BIO.
 * Returns bytes moved. */
static size_t pump(BIO *src, BIO *dst) {
    char buf[16384]; size_t total = 0; int n;
    while ((n = BIO_read(src, buf, sizeof buf)) > 0) {
        BIO_write(dst, buf, n);
        total += (size_t)n;
    }
    return total;
}

/* One full handshake. Records bytes each way and ClientHello size (first flight).
 * Returns 0 on success. */
static int one_handshake(SSL_CTX *cctx, SSL_CTX *sctx,
                         size_t *c2s_bytes, size_t *s2c_bytes, size_t *chello) {
    SSL *cli = SSL_new(cctx), *srv = SSL_new(sctx);
    if (!cli || !srv) { if (cli) SSL_free(cli); if (srv) SSL_free(srv); return -1; }
    BIO *cli_rb = BIO_new(BIO_s_mem()), *cli_wb = BIO_new(BIO_s_mem());
    BIO *srv_rb = BIO_new(BIO_s_mem()), *srv_wb = BIO_new(BIO_s_mem());
    SSL_set_bio(cli, cli_rb, cli_wb);   /* takes ownership */
    SSL_set_bio(srv, srv_rb, srv_wb);
    SSL_set_connect_state(cli);
    SSL_set_accept_state(srv);

    *c2s_bytes = *s2c_bytes = *chello = 0;
    int first_flight = 1, rc = 0;
    for (int i = 0; i < 64; i++) {
        int r_c = SSL_do_handshake(cli);
        size_t moved = pump(cli_wb, srv_rb);
        if (first_flight && moved > 0) { *chello = moved; first_flight = 0; }
        *c2s_bytes += moved;
        (void)r_c;

        int r_s = SSL_do_handshake(srv);
        *s2c_bytes += pump(srv_wb, cli_rb);
        (void)r_s;

        if (SSL_is_init_finished(cli) && SSL_is_init_finished(srv)) break;
        /* if both stalled with nothing to transfer, it's a failure */
        if (BIO_ctrl_pending(cli_wb) == 0 && BIO_ctrl_pending(srv_wb) == 0 &&
            !SSL_is_init_finished(cli) && i > 4) { rc = -2; break; }
    }
    if (!SSL_is_init_finished(cli) || !SSL_is_init_finished(srv)) rc = -2;
    SSL_free(cli); SSL_free(srv);
    return rc;
}

int main(int argc, char **argv) {
    const char *group = "X25519", *ca = NULL, *cert = NULL, *key = NULL, *label = "";
    const char *phase = "", *implementation = "oqs-provider", *sig_alg = "";
    uint64_t connections = 1000, warmup = 20;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--group") && i+1<argc) group = argv[++i];
        else if (!strcmp(argv[i], "--ca") && i+1<argc) ca = argv[++i];
        else if (!strcmp(argv[i], "--cert") && i+1<argc) cert = argv[++i];
        else if (!strcmp(argv[i], "--key") && i+1<argc) key = argv[++i];
        else if (!strcmp(argv[i], "--connections") && i+1<argc) connections = strtoull(argv[++i],0,10);
        else if (!strcmp(argv[i], "--warmup") && i+1<argc) warmup = strtoull(argv[++i],0,10);
        else if (!strcmp(argv[i], "--label") && i+1<argc) label = argv[++i];
        else if (!strcmp(argv[i], "--phase") && i+1<argc) phase = argv[++i];
        else if (!strcmp(argv[i], "--implementation") && i+1<argc) implementation = argv[++i];
        else if (!strcmp(argv[i], "--sig-alg") && i+1<argc) sig_alg = argv[++i];
        else { fprintf(stderr,"bad arg %s\n",argv[i]); return 2; }
    }
    if (!cert || !key) { fprintf(stderr,"--cert and --key required\n"); return 2; }

    /* Providers: default always. oqsprovider is loaded ONLY when measuring
     * implementation "oqs-provider". In native mode ("openssl-native") the
     * provider must not be active at all — a loaded provider can change
     * algorithm availability and negotiation preference, which would make the
     * "native" label a lie — so we additionally ASSERT that no OQS provider
     * is loaded and refuse to emit numbers otherwise. */
    OSSL_PROVIDER_load(NULL, "default");
    int native = strcmp(implementation, "oqs-provider") != 0;
    int have_oqs = 0;
    if (!native)
        have_oqs = OSSL_PROVIDER_load(NULL, "oqsprovider") != NULL;
    else {
        int oqs_active = 0;
        OSSL_PROVIDER_do_all(NULL, check_no_oqs_provider, &oqs_active);
        if (oqs_active) {
            fprintf(stderr, "[bench_tls] FATAL: an OQS provider is active in "
                            "native mode — refusing to emit numbers\n");
            return 1;
        }
    }

    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
    if (!cctx || !sctx) { fprintf(stderr,"ctx alloc failed\n"); return 1; }
    SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sctx, TLS1_3_VERSION);

    int group_ok = SSL_CTX_set1_groups_list(cctx, group) &&
                   SSL_CTX_set1_groups_list(sctx, group);

    int cert_ok = SSL_CTX_use_certificate_chain_file(sctx, cert) == 1 &&
                  SSL_CTX_use_PrivateKey_file(sctx, key, SSL_FILETYPE_PEM) == 1;

    /* client verifies the server chain -> exercises PQ signature verify cost */
    int verify_setup = 1;
    if (ca) {
        if (SSL_CTX_load_verify_locations(cctx, ca, NULL) != 1) verify_setup = 0;
        SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    }

    if (!group_ok || !cert_ok || !verify_setup) {
        printf("{\"label\":\"%s\",\"group\":\"%s\",\"sig_alg\":\"%s\",\"phase\":\"%s\","
               "\"implementation\":\"%s\",\"enabled\":false,\"have_oqs_provider\":%s,"
               "\"reason\":\"%s%s%s\"}\n",
               label, group, sig_alg, phase, implementation, have_oqs?"true":"false",
               group_ok?"":"group-not-supported ",
               cert_ok?"":"cert-load-failed ",
               verify_setup?"":"ca-load-failed");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* warmup */
    size_t c2s, s2c, ch;
    for (uint64_t i = 0; i < warmup; i++) {
        if (one_handshake(cctx, sctx, &c2s, &s2c, &ch) != 0) {
            printf("{\"label\":\"%s\",\"group\":\"%s\",\"sig_alg\":\"%s\",\"phase\":\"%s\","
                   "\"implementation\":\"%s\",\"enabled\":false,"
                   "\"have_oqs_provider\":%s,\"reason\":\"handshake failed\"}\n",
                   label, group, sig_alg, phase, implementation, have_oqs?"true":"false");
            ERR_print_errors_fp(stderr);
            return 0;
        }
    }

    uint64_t *lat = malloc(connections * sizeof(uint64_t));
    size_t ch_last = 0, c2s_last = 0, s2c_last = 0;
    uint64_t ok = 0;
    for (uint64_t i = 0; i < connections; i++) {
        uint64_t t0 = now_ns();
        int rc = one_handshake(cctx, sctx, &c2s, &s2c, &ch);
        uint64_t dt = now_ns() - t0;
        if (rc == 0) { lat[ok++] = dt; ch_last = ch; c2s_last = c2s; s2c_last = s2c; }
    }
    if (ok == 0) { fprintf(stderr,"all handshakes failed\n"); return 1; }
    qsort(lat, ok, sizeof(uint64_t), cmp_u64);
    double median = pct(lat, ok, 0.5);
    double p95 = pct(lat, ok, 0.95);
    double mn = (double)lat[0], mx = (double)lat[ok-1];
    double sum=0; for (uint64_t i=0;i<ok;i++) sum+=(double)lat[i];
    double mean = sum/ok;
    double ss=0; for (uint64_t i=0;i<ok;i++){double d=(double)lat[i]-mean; ss+=d*d;}
    double stddev = ok>1?sqrt(ss/(ok-1)):0;
    double hs_per_sec = median>0 ? 1e9/median : 0;

    printf("{\"label\":\"%s\",\"group\":\"%s\",\"sig_alg\":\"%s\",\"phase\":\"%s\","
           "\"implementation\":\"%s\",\"enabled\":true,\"have_oqs_provider\":%s,",
           label, group, sig_alg, phase, implementation, have_oqs?"true":"false");
    printf("\"connections\":%llu,\"succeeded\":%llu,", (unsigned long long)connections,(unsigned long long)ok);
    printf("\"handshake_latency_ns\":{\"median\":%.1f,\"p95\":%.1f,\"min\":%.1f,\"max\":%.1f,\"mean\":%.1f,\"stddev\":%.1f},",
           median,p95,mn,mx,mean,stddev);
    printf("\"handshakes_per_sec\":%.1f,", hs_per_sec);
    printf("\"bytes_on_wire\":{\"client_to_server\":%zu,\"server_to_client\":%zu,\"total\":%zu},",
           c2s_last, s2c_last, c2s_last+s2c_last);
    printf("\"client_hello_bytes\":%zu,\"client_hello_fragmented\":%s,\"mss_assumed\":%d}\n",
           ch_last, ch_last>TYPICAL_MSS?"true":"false", TYPICAL_MSS);
    free(lat);
    return 0;
}
