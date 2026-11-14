/* grinsight_state.h - C ABI of the GrinSight light-wallet core (stage 2).
 *
 * The host does networking, peer choice, files and clocks. This module does
 * every check that decides what is true: the header chain (PoW, difficulty,
 * linkage, header MMR), the UTXO state from PIBD segments, and blocks, which
 * change the state only if they reproduce the header roots.
 *
 * Return codes: US_OK (0), US_NOT_FOUND (1), negative = error; the message
 * of the last error on the calling thread: us_last_error().
 * Byte formats are Grin's own serialization (headers, blocks, segments);
 * a checkpoint is the RWM1 text file, its history recent-headers.bin.
 * Buffers returned by the module: us_free_buf(); handles: their *_free().
 * The network is per thread: call us_set_network() in every thread.
 *
 * RESEARCH / NOT VERIFIED. No consensus change.
 */
#ifndef GRINSIGHT_STATE_H
#define GRINSIGHT_STATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define US_OK          0
#define US_NOT_FOUND   1
#define US_ERR_ARG    -1  /* bad arguments (null pointers, not text, ...) */
#define US_ERR_REJECT -2  /* verification failed: data is not valid */
#define US_ERR_PANIC  -3  /* internal error */

typedef struct UsHeaders us_headers;
typedef struct UsState us_state;
typedef struct UsSession us_session;
typedef struct { const uint8_t *ptr; size_t len; } us_bytes;

/* General */
const char *us_version(void);
int us_set_network(int mainnet);                    /* 1 mainnet, 0 testnet; per thread */
size_t us_last_error(char *buf, size_t cap);        /* returns full message length */
void us_free_buf(uint8_t *p, size_t n);

/* Header chain: start at a checkpoint, append headers one by one.
 * Every appended header has its network difficulty checked (no "unchecked"
 * mode): the history may be empty only at genesis; otherwise it must cover the
 * difficulty window of the next header, else open returns US_ERR_REJECT. */
int us_headers_open(const uint8_t *checkpoint_rwm, size_t n,
                    const uint8_t *history, size_t hn,  /* empty only at genesis */
                    us_headers **out);
int us_headers_append(us_headers *h, const uint8_t *header, size_t n); /* REJECT keeps chain */
int us_headers_tip(const us_headers *h, uint8_t **out, size_t *n);
uint64_t us_headers_height(const us_headers *h);
void us_headers_free(us_headers *h);

/* UTXO state */
int us_state_from_segments(const uint8_t *archive_header, size_t n,
                           const us_bytes *bitmap_segments, size_t nb,
                           const us_bytes *output_segments, size_t no,
                           us_state **out);          /* REJECT unless output_root matches */
int us_state_load(const uint8_t *file, size_t n, us_state **out,
                  uint8_t **saved_under_header, size_t *hn); /* host checks that header */
int us_state_save(const us_state *s, const uint8_t *header, size_t hn,
                  uint8_t **out, size_t *n);
int us_state_apply_block(us_state *s, const uint8_t *header, size_t hn,
                         const uint8_t *block, size_t bn);  /* REJECT keeps state */
int us_block_validate(const uint8_t *prev_header, size_t pn, /* pn = 0: no prev */
                      const uint8_t *header, size_t hn,
                      const uint8_t *block, size_t bn);    /* consensus body check */
int us_state_lookup(const us_state *s, const uint8_t commit[33], uint64_t *pos);
uint64_t us_state_utxo_count(const us_state *s);
uint64_t us_state_mmr_size(const us_state *s);
int us_state_output_root(const us_state *s, uint8_t out[32]);
void us_state_free(us_state *s);

/* Session and wallet policy (was grinsight.py). Paths and pins: UTF-8, NUL-terminated.
 * JSON results are UTF-8 bytes (not NUL-terminated), freed with us_free_buf(). */
int us_session_open(const char *folder, const char *manifest_sha256,
                    us_session **out);                 /* REJECT: pin or files wrong */
int us_session_summary(const us_session *s, int64_t now_unix,
                       uint8_t **json, size_t *n);     /* tip, status, freshness, can_spend */
int us_session_spend_gate(const us_session *s, int64_t now_unix); /* OK or REJECT + reason */
uint64_t us_session_tip_height(const us_session *s);
int us_session_header_at(const us_session *s, uint64_t height,
                         uint8_t **out, size_t *n);    /* NOT_FOUND outside the transcript */
void us_session_free(us_session *s);
int us_wallet_balance(const uint8_t *known_outputs, size_t kn,
                      const uint8_t *pending_journal, size_t pn,
                      uint32_t wallet,                 /* 1-based */
                      uint8_t **json, size_t *n);      /* available/reserved/incoming/immature */

#ifdef __cplusplus
}
#endif
#endif /* GRINSIGHT_STATE_H */
