/* test_abi.c - the C side of stage 2: build the UTXO state from saved PIBD
 * segments, apply blocks, compare every result with what the Rust core said
 * (expected.txt from us-fixture), and check the rejections.
 *
 *   us-fixture DIR && test_abi DIR
 */
#define _CRT_SECURE_NO_WARNINGS
#include "grinsight_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, ...) do { if (cond) { printf("ok   "); } else { printf("FAIL "); failures++; } \
    printf(__VA_ARGS__); printf("\n"); } while (0)

static uint8_t *read_file(const char *dir, const char *name, size_t *n) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { *n = 0; return NULL; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(len > 0 ? (size_t)len : 1);
    *n = fread(b, 1, (size_t)len, f);
    fclose(f);
    return b;
}

static const char *expected(const char *dir, const char *key) {
    static char val[256];
    size_t n;
    char *t = (char *)read_file(dir, "expected.txt", &n);
    char *s = t;
    val[0] = 0;
    while (s && s < t + n) {
        char *e = memchr(s, '\n', (size_t)(t + n - s));
        size_t l = e ? (size_t)(e - s) : (size_t)(t + n - s);
        size_t k = strlen(key);
        if (l > k && strncmp(s, key, k) == 0 && s[k] == ' ') {
            size_t vl = l - k - 1 < sizeof val - 1 ? l - k - 1 : sizeof val - 1;
            memcpy(val, s + k + 1, vl);
            val[vl] = 0;
            break;
        }
        s = e ? e + 1 : NULL;
    }
    free(t);
    return val;
}

static void hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static void unhex(const char *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
}

static const char *err(void) {
    static char e[512];
    us_last_error(e, sizeof e);
    return e;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: test_abi FIXTURE_DIR\n"); return 2; }
    const char *dir = argv[1];
    printf("%s\n", us_version());
    us_set_network(0);

    /* --- headers --------------------------------------------------------- */
    size_t n, hn;
    uint8_t *rwm = read_file(dir, "genesis.rwm", &n);
    us_headers *hc = NULL;
    int rc = us_headers_open(rwm, n, NULL, 0, &hc);
    CHECK(rc == US_OK && us_headers_height(hc) == 0, "headers: genesis checkpoint opens (rc=%d)", rc);
    uint8_t *bad = read_file(dir, "header_bad_pow.bin", &hn);
    rc = us_headers_append(hc, bad, hn);
    CHECK(rc == US_ERR_REJECT && us_headers_height(hc) == 0, "headers: header without valid PoW rejected, chain unchanged (%s)", err());
    rwm[10] ^= 1; /* corrupt the checkpoint text */
    us_headers *hc2 = NULL;
    CHECK(us_headers_open(rwm, n, NULL, 0, &hc2) != US_OK, "headers: corrupted checkpoint rejected (%s)", err());
    free(rwm); free(bad); us_headers_free(hc);

    /* --- state from segments --------------------------------------------- */
    us_bytes bm[64], out[512];
    size_t nb = 0, no = 0;
    char name[64];
    for (;;) { snprintf(name, sizeof name, "bitmap_%03zu.bin", nb); size_t l; uint8_t *b = read_file(dir, name, &l); if (!b) break; bm[nb].ptr = b; bm[nb].len = l; nb++; }
    for (;;) { snprintf(name, sizeof name, "output_%03zu.bin", no); size_t l; uint8_t *b = read_file(dir, name, &l); if (!b) break; out[no].ptr = b; out[no].len = l; no++; }
    CHECK(nb == (size_t)atoi(expected(dir, "segments_bitmap")) && no == (size_t)atoi(expected(dir, "segments_output")),
          "segments read: bitmap=%zu output=%zu", nb, no);
    size_t an;
    uint8_t *archive = read_file(dir, "archive_header.bin", &an);
    us_state *st = NULL;
    rc = us_state_from_segments(archive, an, bm, nb, out, no, &st);
    CHECK(rc == US_OK && us_state_utxo_count(st) == strtoull(expected(dir, "archive_utxo"), NULL, 10),
          "state from segments matches the archive output_root, utxo=%llu (rc=%d)", (unsigned long long)us_state_utxo_count(st), rc);
    /* a missing segment cannot reproduce the root */
    us_state *st_bad = NULL;
    CHECK(us_state_from_segments(archive, an, bm, nb, out, no - 1, &st_bad) == US_ERR_REJECT, "state: a missing output segment is rejected (%s)", err());

    /* --- blocks ---------------------------------------------------------- */
    uint8_t watched[33];
    unhex(expected(dir, "watched"), watched, 33);
    uint64_t pos = 0;
    CHECK(us_state_lookup(st, watched, &pos) == US_OK, "watched output unspent at the archive (pos %llu)", (unsigned long long)pos);

    size_t h1n, b1n, h2n, b2n, l2n, h3n, b3n;
    uint8_t *h1 = read_file(dir, "header_1.bin", &h1n), *b1 = read_file(dir, "block_1.bin", &b1n);
    uint8_t *h2 = read_file(dir, "header_2.bin", &h2n), *b2 = read_file(dir, "block_2.bin", &b2n);
    uint8_t *l2 = read_file(dir, "block_2_hides_spend.bin", &l2n);
    uint8_t *h3 = read_file(dir, "header_3.bin", &h3n), *b3 = read_file(dir, "block_3.bin", &b3n);
    CHECK(us_state_apply_block(st, h1, h1n, b1, b1n) == US_OK, "block 1 applied");
    uint64_t before = us_state_utxo_count(st);
    CHECK(us_state_apply_block(st, h2, h2n, l2, l2n) == US_ERR_REJECT && us_state_utxo_count(st) == before,
          "block 2 hiding a spend rejected, state unchanged (%s)", err());
    CHECK(us_state_apply_block(st, h3, h3n, b3, b3n) == US_ERR_REJECT, "block 3 before block 2 rejected (%s)", err());
    CHECK(us_state_apply_block(st, h2, h2n, b2, b2n) == US_OK, "honest block 2 applied");
    CHECK(us_state_lookup(st, watched, NULL) == US_NOT_FOUND, "watched output spent in block 2");
    CHECK(us_state_apply_block(st, h3, h3n, b3, b3n) == US_OK, "block 3 applied");

    uint8_t root[32];
    char roothex[65];
    us_state_output_root(st, root);
    hex(root, 32, roothex);
    CHECK(strcmp(roothex, expected(dir, "final_output_root")) == 0, "final output_root equals Rust: %s", roothex);
    CHECK(us_state_utxo_count(st) == strtoull(expected(dir, "final_utxo"), NULL, 10)
          && us_state_mmr_size(st) == strtoull(expected(dir, "final_mmr_size"), NULL, 10),
          "final utxo=%llu mmr_size=%llu equal Rust", (unsigned long long)us_state_utxo_count(st), (unsigned long long)us_state_mmr_size(st));
    uint8_t newc[33];
    unhex(expected(dir, "new_output"), newc, 33);
    CHECK(us_state_lookup(st, newc, &pos) == US_OK && pos == strtoull(expected(dir, "new_output_pos"), NULL, 10),
          "output created in block 2 found at pos %llu", (unsigned long long)pos);

    /* --- save / load ----------------------------------------------------- */
    uint8_t *saved; size_t sn;
    CHECK(us_state_save(st, h3, h3n, &saved, &sn) == US_OK, "state saved (%zu bytes)", sn);
    uint8_t *wrong = NULL; size_t wn = 0;
    CHECK(us_state_save(st, h2, h2n, &wrong, &wn) == US_ERR_REJECT, "saving under the wrong header rejected");
    us_state *st2 = NULL; uint8_t *under; size_t un;
    CHECK(us_state_load(saved, sn, &st2, &under, &un) == US_OK && un == h3n && memcmp(under, h3, un) == 0,
          "state loaded, saved under header 3");
    uint8_t root2[32];
    us_state_output_root(st2, root2);
    CHECK(memcmp(root, root2, 32) == 0 && us_state_utxo_count(st2) == us_state_utxo_count(st), "loaded state equals the original");
    saved[sn / 2] ^= 0x40;
    us_state *st3 = NULL; uint8_t *u3; size_t u3n;
    CHECK(us_state_load(saved, sn, &st3, &u3, &u3n) != US_OK, "tampered state file rejected (%s)", err());

    us_free_buf(saved, sn); us_free_buf(under, un);
    us_state_free(st); us_state_free(st2);
    printf("%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
