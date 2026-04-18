/*
 * scatter — plausible-deniability steganographic scatter tool
 * ============================================================
 *
 * Overview
 * --------
 * scatter takes one or more "payload" files and embeds each of them as a set
 * of encrypted fragments ("chunks") at pseudo-random offsets inside a larger
 * "container" (a regular file or a block device, e.g. a USB stick previously
 * filled with /dev/urandom).
 *
 * Each payload is:
 *   1. Split into variable-length chunks (min_chunk..max_chunk bytes).
 *   2. Each chunk is encrypted with AES-256-GCM using a 256-bit key derived
 *      from a user password via PBKDF2-HMAC-SHA256 (per-payload random salt).
 *   3. Chunks are scattered across the container at non-overlapping offsets,
 *      separated by random gaps [min_gap..max_gap], avoiding head/tail skip
 *      zones. Within the container, chunks from different payloads do NOT
 *      overlap either.
 *
 * The resulting map (offsets, lengths, SHA-256 of ciphertext, salt, chunk id)
 * is written as a *plain-text* human-readable file (the "map file"), so the
 * user can visually inspect, grep, diff, or version-control it. The tool
 * itself parses this same plain-text format on unpack/audit.
 *
 * Security Model
 * --------------
 * Confidentiality:   AES-256-GCM, per-chunk 96-bit IV derived from
 *                    (salt[0..7] || chunk_id_be32). Because the salt is random
 *                    per-payload and included in the IV, the IV never repeats
 *                    across payloads or across runs with the same password.
 * Integrity:         GCM tag authenticates each chunk. On unpack a wrong
 *                    password or tampered byte aborts decryption cleanly.
 * Plausible deniability:
 *                    If the container is pre-filled with /dev/urandom, the
 *                    ciphertext chunks are indistinguishable from the
 *                    surrounding noise without the map file and the password.
 *                    The user must store the map file OUT OF BAND.
 *
 * The tool DOES NOT fill the container with random bytes. The user is
 * expected to do that once with, for example:
 *   dd if=/dev/urandom of=/dev/sdb bs=4M status=progress
 *
 * Map file format (plain text)
 * ----------------------------
 *   # scatter map v2
 *   container=/dev/sdb
 *   container_size=8053063680
 *   skip_head=10
 *   skip_tail=10
 *   created=2026-04-16T12:34:56Z
 *
 *   [payload]
 *   name=secret.zip
 *   original_size=1048576
 *   salt=3f2a9c...            (32 hex chars = 16 bytes)
 *   pbkdf2_iterations=600000
 *   chunk_count=42
 *   # id       offset       length   sha256(ciphertext||tag)
 *   00000000  0x000a3f100  00004096 3f2a9c...
 *   00000001  0x001b2c400  00008208 9c4d81...
 *   ...
 *
 *   [payload]
 *   name=notes.txt
 *   ...
 *
 * Build
 * -----
 *   make                # dynamic build against system OpenSSL
 *   make static-musl    # fully static musl binary (no runtime deps)
 *   make debug          # -O0 -g -fsanitize=address,undefined
 *
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* BLKGETSIZE64 lives in <linux/fs.h>, but including that header drags in
 * types that conflict with musl's own <sys/mount.h>. We only need one ioctl
 * number and one type, so we hard-code them when the kernel header is
 * unavailable. This keeps static-musl builds working without the kernel
 * headers package. */
#if defined(__has_include)
#  if __has_include(<linux/fs.h>)
#    include <linux/fs.h>
#  endif
#endif
#ifndef BLKGETSIZE64
#  define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* ============================================================
 * Constants & configuration
 * ============================================================ */

#define SCATTER_VERSION          "2.1.0"
#define MAP_FORMAT_VERSION       2
#define OPS_FORMAT_VERSION       1

/* Cryptographic parameters. PBKDF2 iteration count matches OWASP 2023
 * guidance for HMAC-SHA256. */
#define PBKDF2_ITERATIONS        600000u
#define KEY_LEN                  32u   /* AES-256 */
#define GCM_IV_LEN               12u
#define GCM_TAG_LEN              16u
#define SALT_LEN                 16u

/* Defaults, overridable via CLI. */
#define DEFAULT_SKIP_HEAD        10u
#define DEFAULT_SKIP_TAIL        10u
#define DEFAULT_MIN_CHUNK        (4u * 1024u)        /*   4 KiB */
#define DEFAULT_MAX_CHUNK        (256u * 1024u)      /* 256 KiB */
#define DEFAULT_MIN_GAP          (4u * 1024u)        /*   4 KiB */
#define DEFAULT_MAX_GAP          (64u * 1024u)       /*  64 KiB */
#define DEFAULT_PLACE_RETRIES    100000u

/* Limit in-memory working set — we never read a whole payload into RAM, but we
 * do allocate chunk buffers. 16 MiB is a sane ceiling for max_chunk. */
#define HARD_MAX_CHUNK           (16u * 1024u * 1024u)

/* Password length ceiling for interactive prompt. */
#define MAX_PASSWORD_LEN         1024u

/* ============================================================
 * Logging
 * ============================================================ */

typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG = 1,
    LOG_INFO  = 2,
    LOG_WARN  = 3,
    LOG_ERROR = 4,
    LOG_FATAL = 5
} LogLevel;

static LogLevel g_log_level = LOG_INFO;
static bool     g_log_color = true;
static FILE    *g_log_stream = NULL;   /* lazily initialised to stderr */

static const char *log_level_name(LogLevel lvl) {
    switch (lvl) {
    case LOG_TRACE: return "TRACE";
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO:  return "INFO ";
    case LOG_WARN:  return "WARN ";
    case LOG_ERROR: return "ERROR";
    case LOG_FATAL: return "FATAL";
    }
    return "?????";
}

static const char *log_level_color(LogLevel lvl) {
    if (!g_log_color) return "";
    switch (lvl) {
    case LOG_TRACE: return "\033[37m";      /* light grey */
    case LOG_DEBUG: return "\033[36m";      /* cyan       */
    case LOG_INFO:  return "\033[32m";      /* green      */
    case LOG_WARN:  return "\033[33m";      /* yellow     */
    case LOG_ERROR: return "\033[31m";      /* red        */
    case LOG_FATAL: return "\033[1;31m";    /* bold red   */
    }
    return "";
}

/* Core logging entry point. Format: "ISO8601 [LEVEL] msg". Always flushed so
 * logs survive a crash. */
static void log_emit(LogLevel lvl, const char *fmt, ...) {
    if (lvl < g_log_level) return;
    if (!g_log_stream) g_log_stream = stderr;

    char ts[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    const char *color = log_level_color(lvl);
    const char *reset = g_log_color ? "\033[0m" : "";

    fprintf(g_log_stream, "%s %s[%s]%s ",
            ts, color, log_level_name(lvl), reset);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log_stream, fmt, ap);
    va_end(ap);

    fputc('\n', g_log_stream);
    fflush(g_log_stream);
}

#define TRACE(...) log_emit(LOG_TRACE, __VA_ARGS__)
#define DEBUG(...) log_emit(LOG_DEBUG, __VA_ARGS__)
#define INFO(...)  log_emit(LOG_INFO,  __VA_ARGS__)
#define WARN(...)  log_emit(LOG_WARN,  __VA_ARGS__)
#define ERRR(...)  log_emit(LOG_ERROR, __VA_ARGS__)  /* ERROR conflicts with some headers */
#define FATAL(...) do { log_emit(LOG_FATAL, __VA_ARGS__); exit(EXIT_FAILURE); } while (0)

/* ============================================================
 * Small helpers
 * ============================================================ */

/**
 * hex_encode - write @len bytes of @in as lowercase hex into @out.
 * @out must have room for 2*@len + 1 bytes; it is NUL-terminated.
 */
static void hex_encode(const unsigned char *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]     = hex[(in[i] >> 4) & 0xF];
        out[2*i + 1] = hex[ in[i]       & 0xF];
    }
    out[2*len] = '\0';
}

/**
 * hex_decode - parse @inlen hex chars from @in into @out (must hold inlen/2
 * bytes). Returns 0 on success, -1 on malformed input.
 */
static int hex_decode(const char *in, size_t inlen, unsigned char *out) {
    if (inlen % 2) return -1;
    for (size_t i = 0; i < inlen / 2; i++) {
        unsigned hi, lo;
        char c = in[2*i], d = in[2*i + 1];
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;
        if      (d >= '0' && d <= '9') lo = d - '0';
        else if (d >= 'a' && d <= 'f') lo = d - 'a' + 10;
        else if (d >= 'A' && d <= 'F') lo = d - 'A' + 10;
        else return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

/**
 * secure_random_u64 - uniform 64-bit value from a CSPRNG. Aborts on RNG failure
 * because we cannot operate safely without entropy.
 */
static uint64_t secure_random_u64(void) {
    uint64_t r;
    if (RAND_bytes((unsigned char *)&r, sizeof r) != 1)
        FATAL("RAND_bytes failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return r;
}

/**
 * random_in_range - uniform integer in the inclusive range [lo, hi].
 * Uses rejection sampling to avoid modulo bias.
 */
static uint64_t random_in_range(uint64_t lo, uint64_t hi) {
    if (lo == hi) return lo;
    if (lo > hi)  FATAL("random_in_range: lo > hi (%" PRIu64 " > %" PRIu64 ")", lo, hi);

    uint64_t range = hi - lo + 1;
    /* Largest multiple of @range that fits in uint64_t. */
    uint64_t limit = UINT64_MAX - (UINT64_MAX % range);
    uint64_t r;
    do {
        r = secure_random_u64();
    } while (r >= limit);
    return lo + (r % range);
}

/**
 * write_all / read_all - wrappers around write/read that handle short I/O.
 * Return 0 on success, -1 on error (errno is preserved from the last
 * syscall).
 */
__attribute__((unused))
static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EIO; return -1; }
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int pread_all(int fd, void *buf, size_t len, off_t off) {
    char *p = buf;
    while (len) {
        ssize_t n = pread(fd, p, len, off);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EIO; return -1; }
        p   += (size_t)n;
        off += n;
        len -= (size_t)n;
    }
    return 0;
}

static int pwrite_all(int fd, const void *buf, size_t len, off_t off) {
    const char *p = buf;
    while (len) {
        ssize_t n = pwrite(fd, p, len, off);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EIO; return -1; }
        p   += (size_t)n;
        off += n;
        len -= (size_t)n;
    }
    return 0;
}

/**
 * get_target_size - return size in bytes of @fd, which may be a regular file
 * or a block device. Returns 0 on unsupported types / ioctl failure.
 */
static uint64_t get_target_size(int fd, const char *path) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        ERRR("fstat(%s): %s", path, strerror(errno));
        return 0;
    }
    if (S_ISBLK(st.st_mode)) {
        uint64_t bytes = 0;
        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
            ERRR("ioctl(BLKGETSIZE64, %s): %s", path, strerror(errno));
            return 0;
        }
        return bytes;
    }
    if (S_ISREG(st.st_mode)) {
        return (uint64_t)st.st_size;
    }
    ERRR("%s is neither a regular file nor a block device", path);
    return 0;
}

/**
 * read_password_file - read password from a file. The first line is used
 * (trailing \r and \n are stripped). Returns a heap-allocated NUL-terminated
 * string; caller must OPENSSL_cleanse + free. NULL on any error.
 *
 * Intended use: `scatter pack -P /run/user/1000/secret.pass ...` where the
 * file lives on tmpfs and is cleaned up by the caller. This avoids the
 * password appearing in /proc/<pid>/cmdline as -p would.
 */
static char *read_password_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { ERRR("open password file %s: %s", path, strerror(errno)); return NULL; }

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    /* Sanity-cap size at MAX_PASSWORD_LEN so a prank file doesn't blow memory. */
    if ((uint64_t)st.st_size >= (uint64_t)MAX_PASSWORD_LEN) {
        ERRR("password file too large (>= %u bytes)", MAX_PASSWORD_LEN);
        close(fd); return NULL;
    }

    char *buf = calloc(1, (size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[n] = '\0';

    /* Cut at first \n or \r. */
    char *nl = strpbrk(buf, "\r\n");
    if (nl) *nl = '\0';
    if (buf[0] == '\0') { free(buf); ERRR("password file is empty"); return NULL; }
    return buf;
}

/* ============================================================
 * Cryptography
 * ============================================================ */

/**
 * derive_key - PBKDF2-HMAC-SHA256 password → 256-bit key.
 * Returns 0 on success, -1 on failure.
 */
static int derive_key(const char *password,
                      const unsigned char *salt,
                      unsigned char *out_key)
{
    DEBUG("PBKDF2-HMAC-SHA256, iterations=%u", PBKDF2_ITERATIONS);
    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, SALT_LEN,
                           PBKDF2_ITERATIONS,
                           EVP_sha256(),
                           KEY_LEN, out_key)) {
        ERRR("PKCS5_PBKDF2_HMAC failed: %s",
             ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    return 0;
}

/**
 * build_iv - derive 96-bit IV from (salt[0..7] || big-endian chunk_id).
 *
 * Why this construction:
 *   - IV must be unique per (key, message) pair. The key is derived from a
 *     per-payload random salt, so reusing (salt_prefix, chunk_id) across
 *     payloads is safe because the key differs.
 *   - Within one payload, chunk_id is unique per chunk, so IVs never repeat.
 *   - Using salt bytes inside the IV also frustrates precomputation attacks
 *     across runs with the same password.
 */
static void build_iv(const unsigned char *salt, uint32_t chunk_id, unsigned char iv[GCM_IV_LEN]) {
    memcpy(iv, salt, 8);
    iv[8]  = (unsigned char)(chunk_id >> 24);
    iv[9]  = (unsigned char)(chunk_id >> 16);
    iv[10] = (unsigned char)(chunk_id >> 8);
    iv[11] = (unsigned char)(chunk_id);
}

/**
 * gcm_encrypt - AES-256-GCM encryption of one chunk. Writes ciphertext (same
 * length as plaintext) and a 16-byte tag. Returns 0 on success, -1 on error.
 */
static int gcm_encrypt(const unsigned char *pt, size_t pt_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *ct, unsigned char *tag)
{
    int ok = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;

    int len = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len)) goto done;
    int total = len;
    if (!EVP_EncryptFinal_ex(ctx, ct + total, &len)) goto done;
    total += len;
    if ((size_t)total != pt_len) goto done;   /* GCM is a stream cipher: must match */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) goto done;
    ok = 0;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ok != 0) ERRR("gcm_encrypt: %s", ERR_error_string(ERR_get_error(), NULL));
    return ok;
}

/**
 * gcm_decrypt - AES-256-GCM decryption and authentication of one chunk.
 * Returns 0 on success, -1 on cipher error, -2 on tag mismatch.
 */
static int gcm_decrypt(const unsigned char *ct, size_t ct_len,
                       const unsigned char *tag,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *pt)
{
    int rc = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;

    int len = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (!EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len)) goto done;
    int total = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag)) goto done;
    int fin_ret = EVP_DecryptFinal_ex(ctx, pt + total, &len);
    if (fin_ret <= 0) { rc = -2; goto done; }   /* authentication failure */
    total += len;
    if ((size_t)total != ct_len) { rc = -2; goto done; }
    rc = 0;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ============================================================
 * Data model
 * ============================================================ */

typedef struct {
    uint32_t id;
    uint64_t offset;          /* absolute byte offset inside container */
    uint32_t length;          /* ciphertext length + GCM_TAG_LEN        */
    unsigned char sha256[32]; /* SHA-256 of (ciphertext||tag)           */
} Chunk;

typedef struct {
    char         *name;                 /* payload file name as stored in map */
    uint64_t      original_size;        /* plaintext size                     */
    unsigned char salt[SALT_LEN];
    uint32_t      chunk_count;
    Chunk        *chunks;               /* length = chunk_count               */
} Payload;

typedef struct {
    char     *container_path;
    uint64_t  container_size;
    uint64_t  skip_head;
    uint64_t  skip_tail;
    char     *created;                  /* ISO-8601 timestamp */
    Payload  *payloads;                 /* length = payload_count */
    size_t    payload_count;
} MapFile;

typedef struct {
    uint64_t offset;
    uint64_t length;
} Reservation;

typedef struct {
    Reservation *items;
    size_t       count;
    size_t       cap;
} ReservList;

static void reserv_free(ReservList *r) {
    free(r->items);
    r->items = NULL; r->count = r->cap = 0;
}

static int reserv_push(ReservList *r, uint64_t off, uint64_t len) {
    if (r->count == r->cap) {
        size_t ncap = r->cap ? r->cap * 2 : 64;
        Reservation *p = realloc(r->items, ncap * sizeof *p);
        if (!p) return -1;
        r->items = p; r->cap = ncap;
    }
    r->items[r->count].offset = off;
    r->items[r->count].length = len;
    r->count++;
    return 0;
}

/* ============================================================
 * Layout generator
 * ============================================================
 *
 * Strategy
 * --------
 * For each chunk:
 *   1. Pick a random length in [min_chunk, max_chunk] (capped by remaining
 *      payload bytes). Chunk stored size is length + GCM_TAG_LEN.
 *   2. Pick a random gap in [min_gap, max_gap].
 *   3. Pick a random candidate offset in the allowed window
 *      [skip_head, container_size - skip_tail - stored_len].
 *   4. Reject if the candidate (expanded by `gap` on both sides) overlaps any
 *      existing reservation (from this payload OR any previously-processed
 *      payload in this run). Retry up to PLACE_RETRIES times.
 *   5. Commit: record the reservation and emit a Chunk.
 *
 * The random chunk lengths ensure the last chunk is always >= min_chunk:
 * we pick len = min(rand_len, remaining), but if remaining < min_chunk we
 * clamp the previous chunk so the tail is absorbed — see generate_chunks().
 */

typedef struct {
    uint64_t container_size;
    uint64_t skip_head;
    uint64_t skip_tail;
    uint32_t min_chunk;
    uint32_t max_chunk;
    uint32_t min_gap;
    uint32_t max_gap;
    uint32_t place_retries;
} LayoutCfg;

/**
 * reservation_overlaps - does [off, off+len) intersect any existing
 * reservation expanded by `gap` bytes on each side?
 * Uses overflow-safe arithmetic via uint64_t clamping.
 */
static bool reservation_overlaps(const ReservList *res,
                                 uint64_t off, uint64_t len,
                                 uint64_t gap)
{
    uint64_t cand_start = off;
    uint64_t cand_end   = off + len;      /* caller ensures no overflow */

    for (size_t i = 0; i < res->count; i++) {
        uint64_t s = res->items[i].offset;
        uint64_t e = res->items[i].length;   /* length, not end yet */
        /* expanded interval [s - gap, s + e + gap), clamped */
        uint64_t ex_start = (s > gap) ? (s - gap) : 0;
        uint64_t ex_end   = s + e + gap;
        if (ex_end < s) ex_end = UINT64_MAX;  /* overflow guard */
        /* Overlap if ranges intersect: !(cand_end <= ex_start || cand_start >= ex_end) */
        if (!(cand_end <= ex_start || cand_start >= ex_end))
            return true;
    }
    return false;
}

/**
 * plan_chunk_lengths - split payload_size into chunk_count pieces each in
 * [min_chunk..max_chunk], returning the list of lengths. Returns NULL on
 * failure (payload too small, etc.). Caller frees.
 *
 * Algorithm: keep emitting random lengths in range until remaining < min_chunk;
 * then merge the tail into the previous chunk (possibly producing a last chunk
 * slightly above max_chunk, which we cap by further splitting).
 */
static uint32_t *plan_chunk_lengths(uint64_t payload_size,
                                    uint32_t min_chunk, uint32_t max_chunk,
                                    uint32_t *out_count)
{
    if (payload_size == 0) { *out_count = 0; return NULL; }
    if (payload_size < min_chunk) {
        /* One short chunk — allowed for tiny payloads. */
        uint32_t *arr = malloc(sizeof(uint32_t));
        if (!arr) return NULL;
        arr[0] = (uint32_t)payload_size;
        *out_count = 1;
        return arr;
    }

    size_t cap = 64, n = 0;
    uint32_t *arr = malloc(cap * sizeof(uint32_t));
    if (!arr) return NULL;

    uint64_t remaining = payload_size;
    while (remaining > 0) {
        uint32_t len;
        if (remaining <= max_chunk) {
            /* Final piece. If remaining < min_chunk and we have a prior chunk,
             * merge into prior (keeping <= max_chunk by splitting if needed). */
            if (remaining < min_chunk && n > 0) {
                uint32_t prev = arr[n - 1];
                uint64_t combined = (uint64_t)prev + remaining;
                if (combined <= max_chunk) {
                    arr[n - 1] = (uint32_t)combined;
                } else {
                    /* Split prev: keep at min_chunk, put the rest here. */
                    uint32_t take = (uint32_t)(combined - min_chunk);
                    if (take > max_chunk) take = max_chunk;
                    arr[n - 1] = min_chunk;
                    if (n == cap) {
                        cap *= 2;
                        uint32_t *p = realloc(arr, cap * sizeof(uint32_t));
                        if (!p) { free(arr); return NULL; }
                        arr = p;
                    }
                    arr[n++] = take;
                }
                break;
            }
            len = (uint32_t)remaining;
        } else {
            len = (uint32_t)random_in_range(min_chunk, max_chunk);
            if (len > remaining) len = (uint32_t)remaining;
        }

        if (n == cap) {
            cap *= 2;
            uint32_t *p = realloc(arr, cap * sizeof(uint32_t));
            if (!p) { free(arr); return NULL; }
            arr = p;
        }
        arr[n++] = len;
        remaining -= len;
    }

    *out_count = (uint32_t)n;
    return arr;
}

/**
 * layout_payload - generate a scatter layout for a single payload.
 * Uses the shared @res reservation list so chunks from different payloads
 * cannot overlap.
 *
 * @out_chunks  allocated on success, caller frees
 * @out_count   number of chunks written
 *
 * Returns 0 on success, -1 on error (fragmentation, OOM, bad params).
 */
static int layout_payload(const LayoutCfg *cfg,
                          uint64_t payload_size,
                          ReservList *res,
                          Chunk **out_chunks, uint32_t *out_count)
{
    /* Usable window inside the container. */
    if (cfg->skip_head + cfg->skip_tail >= cfg->container_size) {
        ERRR("skip_head+skip_tail (%" PRIu64 ") >= container size (%" PRIu64 ")",
             cfg->skip_head + cfg->skip_tail, cfg->container_size);
        return -1;
    }
    uint64_t usable_lo = cfg->skip_head;
    uint64_t usable_hi = cfg->container_size - cfg->skip_tail;  /* exclusive */

    uint32_t piece_count = 0;
    uint32_t *piece_lens = plan_chunk_lengths(payload_size,
                                              cfg->min_chunk, cfg->max_chunk,
                                              &piece_count);
    if (!piece_lens) { ERRR("plan_chunk_lengths failed"); return -1; }

    Chunk *chunks = calloc(piece_count, sizeof(Chunk));
    if (!chunks) { free(piece_lens); return -1; }

    for (uint32_t i = 0; i < piece_count; i++) {
        uint32_t stored_len = piece_lens[i] + GCM_TAG_LEN;
        uint64_t gap = random_in_range(cfg->min_gap, cfg->max_gap);

        if (stored_len > usable_hi - usable_lo) {
            ERRR("chunk %u (stored %u B) larger than usable window", i, stored_len);
            free(piece_lens); free(chunks); return -1;
        }

        uint64_t cand = 0;
        bool placed = false;
        for (uint32_t t = 0; t < cfg->place_retries; t++) {
            /* candidate offset in [usable_lo, usable_hi - stored_len] */
            cand = random_in_range(usable_lo, usable_hi - stored_len);
            if (!reservation_overlaps(res, cand, stored_len, gap)) {
                placed = true;
                break;
            }
        }
        if (!placed) {
            ERRR("cannot place chunk %u/%u after %u retries — container too small or too fragmented",
                 i, piece_count, cfg->place_retries);
            free(piece_lens); free(chunks); return -1;
        }

        chunks[i].id     = i;
        chunks[i].offset = cand;
        chunks[i].length = stored_len;

        if (reserv_push(res, cand, stored_len) != 0) {
            ERRR("reserv_push: OOM"); free(piece_lens); free(chunks); return -1;
        }
        TRACE("planned chunk %u: offset=0x%" PRIx64 " len=%u", i, cand, stored_len);
    }

    free(piece_lens);
    *out_chunks = chunks;
    *out_count  = piece_count;
    return 0;
}

/* ============================================================
 * Map file I/O (plain-text)
 * ============================================================ */

/**
 * write_map_file - serialise a MapFile struct to a plain-text file.
 * File is created 0600. Written atomically via rename().
 *
 * The map is the human-readable "debug/info" view. Parsers that only care
 * about offsets can use the much simpler ops-file format (see write_ops_file).
 */
static int write_map_file(const MapFile *mf, const char *path) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        ERRR("map path too long");
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { ERRR("open(%s): %s", tmp, strerror(errno)); return -1; }

    FILE *f = fdopen(fd, "w");
    if (!f) { ERRR("fdopen: %s", strerror(errno)); close(fd); return -1; }

    /* Aggregate statistics across all payloads. */
    uint64_t grand_chunks = 0, grand_stored = 0, grand_plain = 0;
    uint64_t min_off = UINT64_MAX, max_off_end = 0;
    for (size_t p = 0; p < mf->payload_count; p++) {
        const Payload *pl = &mf->payloads[p];
        grand_chunks += pl->chunk_count;
        grand_plain  += pl->original_size;
        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            const Chunk *c = &pl->chunks[i];
            grand_stored += c->length;
            if (c->offset < min_off) min_off = c->offset;
            if (c->offset + c->length > max_off_end) max_off_end = c->offset + c->length;
        }
    }
    double density = mf->container_size
        ? (double)grand_stored * 100.0 / (double)mf->container_size
        : 0.0;

    fprintf(f, "# ============================================================\n");
    fprintf(f, "# scatter map v%d — human-readable layout & audit file\n", MAP_FORMAT_VERSION);
    fprintf(f, "# generated by: scatter %s (%s)\n", SCATTER_VERSION, OpenSSL_version(OPENSSL_VERSION));
    fprintf(f, "# ------------------------------------------------------------\n");
    fprintf(f, "# WARNING: this file + the password are sufficient to recover\n");
    fprintf(f, "# all payloads. Store it separately from the container.\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "format_version=%d\n",              MAP_FORMAT_VERSION);
    fprintf(f, "tool_version=%s\n",                SCATTER_VERSION);
    fprintf(f, "container=%s\n",                   mf->container_path);
    fprintf(f, "container_size=%" PRIu64 "\n",     mf->container_size);
    fprintf(f, "skip_head=%" PRIu64 "\n",          mf->skip_head);
    fprintf(f, "skip_tail=%" PRIu64 "\n",          mf->skip_tail);
    fprintf(f, "created=%s\n",                     mf->created);
    fprintf(f, "\n");
    fprintf(f, "# -- aggregate statistics (informational, not parsed on read) --\n");
    fprintf(f, "# payload_count=%zu\n",            mf->payload_count);
    fprintf(f, "# total_chunks=%" PRIu64 "\n",     grand_chunks);
    fprintf(f, "# total_plaintext_bytes=%" PRIu64 "\n", grand_plain);
    fprintf(f, "# total_ciphertext_bytes=%" PRIu64 "\n", grand_stored);
    fprintf(f, "# container_usage=%.3f%%\n",       density);
    if (grand_chunks) {
        fprintf(f, "# earliest_offset=0x%010" PRIx64 "\n", min_off);
        fprintf(f, "# latest_end=0x%010" PRIx64 "\n",      max_off_end);
    }
    fprintf(f, "\n");

    for (size_t p = 0; p < mf->payload_count; p++) {
        const Payload *pl = &mf->payloads[p];
        char salt_hex[SALT_LEN * 2 + 1];
        hex_encode(pl->salt, SALT_LEN, salt_hex);

        /* Per-payload stats. */
        uint32_t pmin = UINT32_MAX, pmax = 0;
        uint64_t pmin_off = UINT64_MAX, pmax_off = 0;
        uint64_t psum_stored = 0;
        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            const Chunk *c = &pl->chunks[i];
            uint32_t plain = c->length - GCM_TAG_LEN;
            if (plain < pmin) pmin = plain;
            if (plain > pmax) pmax = plain;
            if (c->offset < pmin_off) pmin_off = c->offset;
            if (c->offset + c->length > pmax_off) pmax_off = c->offset + c->length;
            psum_stored += c->length;
        }

        fprintf(f, "# ------------------------------------------------------------\n");
        fprintf(f, "# payload %zu / %zu: %s\n", p + 1, mf->payload_count, pl->name);
        fprintf(f, "# ------------------------------------------------------------\n");
        fprintf(f, "[payload]\n");
        fprintf(f, "name=%s\n",                    pl->name);
        fprintf(f, "original_size=%" PRIu64 "\n",  pl->original_size);
        fprintf(f, "salt=%s\n",                    salt_hex);
        fprintf(f, "pbkdf2_iterations=%u\n",       PBKDF2_ITERATIONS);
        fprintf(f, "cipher=aes-256-gcm\n");
        fprintf(f, "iv_scheme=salt8_be_chunkid4\n");
        fprintf(f, "chunk_count=%u\n",             pl->chunk_count);
        if (pl->chunk_count) {
            fprintf(f, "# min_plaintext_chunk=%u\n",  pmin);
            fprintf(f, "# max_plaintext_chunk=%u\n",  pmax);
            fprintf(f, "# earliest_offset=0x%010" PRIx64 "\n", pmin_off);
            fprintf(f, "# latest_end=0x%010" PRIx64 "\n",      pmax_off);
            fprintf(f, "# ciphertext_bytes=%" PRIu64 "\n",     psum_stored);
        }
        fprintf(f,
            "# id        offset        length   sha256(ciphertext||tag)\n");

        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            const Chunk *c = &pl->chunks[i];
            char digest[65];
            hex_encode(c->sha256, 32, digest);
            fprintf(f, "%08u  0x%010" PRIx64 "  %08u %s\n",
                    c->id, c->offset, c->length, digest);
        }
        fprintf(f, "# end of payload %s (%u chunks)\n", pl->name, pl->chunk_count);
        fprintf(f, "\n");
    }

    fprintf(f, "# -- end of map --\n");

    if (fflush(f) != 0) { ERRR("fflush: %s", strerror(errno)); fclose(f); return -1; }
    if (fsync(fileno(f)) != 0) { WARN("fsync map: %s", strerror(errno)); }
    if (fclose(f) != 0) { ERRR("fclose: %s", strerror(errno)); return -1; }

    if (rename(tmp, path) != 0) {
        ERRR("rename(%s -> %s): %s", tmp, path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    INFO("map file written: %s (%zu payloads, %" PRIu64 " chunks, %.3f%% usage)",
         path, mf->payload_count, grand_chunks, density);
    return 0;
}

/**
 * write_ops_file - minimal machine-friendly "ops" file.
 *
 * Format (strictly positional, one token per line, `#` for comments):
 *
 *   # scatter ops v1
 *   V 1
 *   C <container_path>
 *   S <container_size>
 *   H <skip_head>
 *   T <skip_tail>
 *   P <payload_name>
 *   N <original_size>
 *   K <salt_hex>
 *   I <pbkdf2_iterations>
 *   # For each chunk: three lines (offset, length, sha256).
 *   O 0x0024ab75e5
 *   L 3367
 *   D c84b9f54b6187bbdaa3e7e4a2cc329254ae1652221071a4e169607986d9e6b36
 *   O ...
 *   ...
 *   E <payload_name>         <- end marker
 *
 * Advantages over parsing the full map:
 *   - No variable-width columns, no whitespace sensitivity.
 *   - Each record is a single letter + single value: trivial to parse with
 *     any language, no regex, no integer-overflow gotchas (each numeric field
 *     is validated on read with strtoull + bounds check).
 *   - Comments and unknown tags are ignored — forward-compatible.
 */
static int write_ops_file(const MapFile *mf, const char *path) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        ERRR("ops path too long"); return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { ERRR("open(%s): %s", tmp, strerror(errno)); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }

    fprintf(f, "# scatter ops v%d — machine-parseable extraction file\n", OPS_FORMAT_VERSION);
    fprintf(f, "# generated by: scatter %s\n", SCATTER_VERSION);
    fprintf(f, "V %d\n", OPS_FORMAT_VERSION);
    fprintf(f, "C %s\n", mf->container_path);
    fprintf(f, "S %" PRIu64 "\n", mf->container_size);
    fprintf(f, "H %" PRIu64 "\n", mf->skip_head);
    fprintf(f, "T %" PRIu64 "\n", mf->skip_tail);

    for (size_t p = 0; p < mf->payload_count; p++) {
        const Payload *pl = &mf->payloads[p];
        char salt_hex[SALT_LEN * 2 + 1];
        hex_encode(pl->salt, SALT_LEN, salt_hex);
        fprintf(f, "P %s\n",                 pl->name);
        fprintf(f, "N %" PRIu64 "\n",        pl->original_size);
        fprintf(f, "K %s\n",                 salt_hex);
        fprintf(f, "I %u\n",                 PBKDF2_ITERATIONS);
        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            const Chunk *c = &pl->chunks[i];
            char digest[65];
            hex_encode(c->sha256, 32, digest);
            fprintf(f, "O 0x%010" PRIx64 "\n", c->offset);
            fprintf(f, "L %u\n",                c->length);
            fprintf(f, "D %s\n",                digest);
        }
        fprintf(f, "E %s\n", pl->name);
    }

    if (fflush(f) != 0)                { fclose(f); return -1; }
    if (fsync(fileno(f)) != 0)         WARN("fsync ops: %s", strerror(errno));
    if (fclose(f) != 0)                return -1;
    if (rename(tmp, path) != 0)        { unlink(tmp); return -1; }
    INFO("ops file written: %s", path);
    return 0;
}

static char *str_trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

static void mapfile_free(MapFile *mf) {
    if (!mf) return;
    free(mf->container_path);
    free(mf->created);
    for (size_t i = 0; i < mf->payload_count; i++) {
        free(mf->payloads[i].name);
        free(mf->payloads[i].chunks);
    }
    free(mf->payloads);
    memset(mf, 0, sizeof *mf);
}

/**
 * read_map_file - parse the plain-text map format. Returns 0 on success,
 * -1 on any parse error.
 */
static int read_map_file(const char *path, MapFile *out) {
    memset(out, 0, sizeof *out);

    FILE *f = fopen(path, "r");
    if (!f) { ERRR("open map %s: %s", path, strerror(errno)); return -1; }

    char line[4096];
    Payload *cur = NULL;
    uint32_t cur_chunk_idx = 0;
    int lineno = 0;
    int in_chunks = 0;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *s = str_trim(line);
        if (*s == '\0' || *s == '#') continue;

        if (strcmp(s, "[payload]") == 0) {
            Payload *np = realloc(out->payloads, (out->payload_count + 1) * sizeof(Payload));
            if (!np) { ERRR("OOM"); goto fail; }
            out->payloads = np;
            cur = &out->payloads[out->payload_count++];
            memset(cur, 0, sizeof *cur);
            cur_chunk_idx = 0;
            in_chunks = 0;
            continue;
        }

        char *eq = strchr(s, '=');
        if (eq && !in_chunks) {
            *eq = '\0';
            char *k = str_trim(s);
            char *v = str_trim(eq + 1);

            if (!cur) {
                if      (!strcmp(k, "container"))      out->container_path = strdup(v);
                else if (!strcmp(k, "container_size")) out->container_size = strtoull(v, NULL, 10);
                else if (!strcmp(k, "skip_head"))      out->skip_head      = strtoull(v, NULL, 10);
                else if (!strcmp(k, "skip_tail"))      out->skip_tail      = strtoull(v, NULL, 10);
                else if (!strcmp(k, "created"))        out->created        = strdup(v);
                else if (!strcmp(k, "format_version") ||
                         !strcmp(k, "tool_version"))   TRACE("map %s=%s", k, v);
                else WARN("unknown global key on line %d: %s", lineno, k);
            } else {
                if      (!strcmp(k, "name"))              cur->name          = strdup(v);
                else if (!strcmp(k, "original_size"))     cur->original_size = strtoull(v, NULL, 10);
                else if (!strcmp(k, "salt")) {
                    if (strlen(v) != SALT_LEN * 2 || hex_decode(v, SALT_LEN * 2, cur->salt) != 0) {
                        ERRR("bad salt on line %d", lineno); goto fail;
                    }
                } else if (!strcmp(k, "pbkdf2_iterations")) {
                    unsigned long it = strtoul(v, NULL, 10);
                    if (it != PBKDF2_ITERATIONS) {
                        WARN("map uses pbkdf2_iterations=%lu, tool built with %u — attempting anyway",
                             it, PBKDF2_ITERATIONS);
                    }
                } else if (!strcmp(k, "chunk_count")) {
                    cur->chunk_count = (uint32_t)strtoul(v, NULL, 10);
                    cur->chunks = calloc(cur->chunk_count, sizeof(Chunk));
                    if (!cur->chunks) { ERRR("OOM"); goto fail; }
                    in_chunks = 1;
                }
                else if (!strcmp(k, "cipher") || !strcmp(k, "iv_scheme"))
                    TRACE("map payload %s=%s", k, v);
                else WARN("unknown payload key on line %d: %s", lineno, k);
            }
            continue;
        }

        /* Chunk line: "id  0xoffset  length  sha256" */
        if (cur && in_chunks) {
            if (cur_chunk_idx >= cur->chunk_count) {
                ERRR("too many chunk lines for payload '%s' (line %d)",
                     cur->name ? cur->name : "?", lineno);
                goto fail;
            }
            Chunk *c = &cur->chunks[cur_chunk_idx];
            char digest[65] = {0};
            unsigned long long off = 0;
            unsigned id = 0, len = 0;
            int got = sscanf(s, "%u %llx %u %64s", &id, &off, &len, digest);
            if (got != 4 || strlen(digest) != 64) {
                ERRR("malformed chunk line %d: %s", lineno, s);
                goto fail;
            }
            c->id = id; c->offset = off; c->length = len;
            if (hex_decode(digest, 64, c->sha256) != 0) {
                ERRR("bad sha256 on line %d", lineno); goto fail;
            }
            cur_chunk_idx++;
            continue;
        }

        WARN("ignoring unrecognized line %d: %s", lineno, s);
    }

    fclose(f);

    /* Validate. */
    if (!out->container_path) { ERRR("map missing container="); goto fail_noclose; }
    if (!out->container_size) { ERRR("map missing container_size="); goto fail_noclose; }
    for (size_t p = 0; p < out->payload_count; p++) {
        if (!out->payloads[p].name) { ERRR("payload #%zu missing name", p); goto fail_noclose; }
    }
    return 0;

fail:
    fclose(f);
fail_noclose:
    mapfile_free(out);
    return -1;
}

/**
 * read_ops_file - parse the minimal ops format. Tolerant to blank lines and
 * '#' comments. Each payload is introduced by `P name`, terminated by
 * `E name`, and contains triples of O/L/D lines. Returns 0 on success.
 *
 * Because every field is a single letter + single token, the parser is
 * trivially safe: we do not need to tokenize whitespace-separated columns,
 * and numeric fields use strtoull with explicit range checks.
 */
static int read_ops_file(const char *path, MapFile *out) {
    memset(out, 0, sizeof *out);
    FILE *f = fopen(path, "r");
    if (!f) { ERRR("open ops %s: %s", path, strerror(errno)); return -1; }

    char line[4096];
    int lineno = 0;
    Payload *cur = NULL;
    size_t chunk_cap = 0;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *s = str_trim(line);
        if (*s == '\0' || *s == '#') continue;
        if (strlen(s) < 3 || s[1] != ' ') {
            ERRR("ops line %d: expected 'X value', got: %s", lineno, s);
            goto fail;
        }
        char tag = s[0];
        char *v = str_trim(s + 2);

        switch (tag) {
        case 'V': {
            int vv = atoi(v);
            if (vv != OPS_FORMAT_VERSION)
                WARN("ops format v%d, tool built for v%d — attempting anyway", vv, OPS_FORMAT_VERSION);
            break;
        }
        case 'C': free(out->container_path); out->container_path = strdup(v); break;
        case 'S': out->container_size = strtoull(v, NULL, 0); break;
        case 'H': out->skip_head      = strtoull(v, NULL, 0); break;
        case 'T': out->skip_tail      = strtoull(v, NULL, 0); break;
        case 'P': {
            Payload *np = realloc(out->payloads, (out->payload_count + 1) * sizeof(Payload));
            if (!np) { ERRR("OOM"); goto fail; }
            out->payloads = np;
            cur = &out->payloads[out->payload_count++];
            memset(cur, 0, sizeof *cur);
            cur->name = strdup(v);
            chunk_cap = 0;
            break;
        }
        case 'N': if (!cur) goto no_payload; cur->original_size = strtoull(v, NULL, 0); break;
        case 'K': {
            if (!cur) goto no_payload;
            if (strlen(v) != SALT_LEN * 2 || hex_decode(v, SALT_LEN * 2, cur->salt) != 0) {
                ERRR("ops line %d: bad salt", lineno); goto fail;
            }
            break;
        }
        case 'I': {
            if (!cur) goto no_payload;
            unsigned long it = strtoul(v, NULL, 0);
            if (it != PBKDF2_ITERATIONS)
                WARN("ops uses pbkdf2_iterations=%lu, tool built with %u", it, PBKDF2_ITERATIONS);
            break;
        }
        case 'O': {
            if (!cur) goto no_payload;
            if (cur->chunk_count == chunk_cap) {
                size_t ncap = chunk_cap ? chunk_cap * 2 : 16;
                Chunk *nc = realloc(cur->chunks, ncap * sizeof(Chunk));
                if (!nc) { ERRR("OOM"); goto fail; }
                cur->chunks = nc; chunk_cap = ncap;
                memset(&cur->chunks[cur->chunk_count], 0,
                       (ncap - cur->chunk_count) * sizeof(Chunk));
            }
            cur->chunks[cur->chunk_count].id     = cur->chunk_count;
            cur->chunks[cur->chunk_count].offset = strtoull(v, NULL, 0);
            cur->chunk_count++;
            break;
        }
        case 'L': {
            if (!cur || cur->chunk_count == 0) goto no_chunk;
            unsigned long L = strtoul(v, NULL, 0);
            if (L == 0 || L > HARD_MAX_CHUNK + GCM_TAG_LEN) {
                ERRR("ops line %d: bad length %lu", lineno, L); goto fail;
            }
            cur->chunks[cur->chunk_count - 1].length = (uint32_t)L;
            break;
        }
        case 'D': {
            if (!cur || cur->chunk_count == 0) goto no_chunk;
            if (strlen(v) != 64 ||
                hex_decode(v, 64, cur->chunks[cur->chunk_count - 1].sha256) != 0) {
                ERRR("ops line %d: bad sha256", lineno); goto fail;
            }
            break;
        }
        case 'E': {
            if (!cur || !cur->name || strcmp(cur->name, v) != 0) {
                ERRR("ops line %d: mismatched 'E %s' (expected %s)",
                     lineno, v, cur ? cur->name : "(none)");
                goto fail;
            }
            cur = NULL;
            chunk_cap = 0;
            break;
        }
        default:
            TRACE("ops line %d: ignoring unknown tag '%c'", lineno, tag);
            break;
        }
    }
    fclose(f);

    if (!out->container_path || !out->container_size) {
        ERRR("ops file missing C/S headers"); mapfile_free(out); return -1;
    }
    return 0;

no_payload:
    ERRR("ops line %d: record before [P]ayload", lineno); goto fail;
no_chunk:
    ERRR("ops line %d: L/D before O", lineno); goto fail;
fail:
    fclose(f);
    mapfile_free(out);
    return -1;
}

/**
 * load_any_map - auto-detect map vs ops by first non-comment line and dispatch.
 */
static int load_any_map(const char *path, MapFile *out) {
    FILE *f = fopen(path, "r");
    if (!f) { ERRR("open %s: %s", path, strerror(errno)); return -1; }
    char line[4096];
    int kind = 0;   /* 0=unknown, 1=map, 2=ops */
    while (fgets(line, sizeof line, f)) {
        char *s = str_trim(line);
        if (*s == '\0' || *s == '#') continue;
        /* ops lines are "<letter> <value>" */
        if (strlen(s) >= 3 && s[1] == ' ' && strchr("VCSHTPNKIOLDE", s[0])) kind = 2;
        else kind = 1;
        break;
    }
    fclose(f);
    if (kind == 2) {
        DEBUG("%s detected as ops format", path);
        return read_ops_file(path, out);
    }
    DEBUG("%s detected as map format", path);
    return read_map_file(path, out);
}

/* ============================================================
 * Actions: pack / unpack / audit
 * ============================================================ */

typedef struct {
    /* common */
    LogLevel log_level;

    /* pack */
    const char **input_files;   /* array of paths */
    size_t       input_count;
    const char  *container;
    const char  *map_path;
    const char  *ops_path;      /* optional: minimal production ops file      */
    const char  *password_cli;  /* either -p PASS or contents of -P FILE      */
    uint64_t     skip_head;
    uint64_t     skip_tail;
    uint32_t     min_chunk;
    uint32_t     max_chunk;
    uint32_t     min_gap;
    uint32_t     max_gap;

    /* unpack */
    const char  *output_dir;    /* directory, each payload restored to output_dir/name */
    const char  *only_name;     /* restrict unpack to this payload name (NULL = all) */
} Args;

/**
 * iso8601_now - fill @buf (>= 21 bytes) with current UTC time.
 */
static void iso8601_now(char *buf, size_t cap) {
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
}

/**
 * action_pack - encrypt and scatter each input file into the container, then
 * emit a plain-text map file describing the layout.
 */
static int action_pack(const Args *a, char *password) {
    INFO("pack: %zu input file(s) → %s (map: %s)",
         a->input_count, a->container, a->map_path);

    int fd_cont = open(a->container, O_WRONLY);
    if (fd_cont < 0) { ERRR("open container %s: %s", a->container, strerror(errno)); return -1; }

    uint64_t cont_size = get_target_size(fd_cont, a->container);
    if (cont_size == 0) { close(fd_cont); return -1; }
    INFO("container: %s — %" PRIu64 " bytes", a->container, cont_size);

    LayoutCfg cfg = {
        .container_size = cont_size,
        .skip_head      = a->skip_head,
        .skip_tail      = a->skip_tail,
        .min_chunk      = a->min_chunk,
        .max_chunk      = a->max_chunk,
        .min_gap        = a->min_gap,
        .max_gap        = a->max_gap,
        .place_retries  = DEFAULT_PLACE_RETRIES,
    };

    MapFile mf = {0};
    mf.container_path = strdup(a->container);
    mf.container_size = cont_size;
    mf.skip_head = a->skip_head;
    mf.skip_tail = a->skip_tail;
    char ts[32]; iso8601_now(ts, sizeof ts);
    mf.created = strdup(ts);

    ReservList res = {0};
    int rc = -1;

    mf.payloads = calloc(a->input_count, sizeof(Payload));
    if (!mf.payloads) { ERRR("OOM"); goto cleanup; }
    mf.payload_count = a->input_count;

    for (size_t p = 0; p < a->input_count; p++) {
        const char *path = a->input_files[p];
        Payload *pl = &mf.payloads[p];

        int fd_in = open(path, O_RDONLY);
        if (fd_in < 0) { ERRR("open payload %s: %s", path, strerror(errno)); goto cleanup; }
        struct stat st;
        if (fstat(fd_in, &st) != 0) { ERRR("fstat: %s", strerror(errno)); close(fd_in); goto cleanup; }
        if (st.st_size == 0) { ERRR("payload %s is empty", path); close(fd_in); goto cleanup; }

        /* name = basename only */
        const char *base = strrchr(path, '/');
        base = base ? base + 1 : path;
        pl->name = strdup(base);
        pl->original_size = (uint64_t)st.st_size;

        if (RAND_bytes(pl->salt, SALT_LEN) != 1) {
            ERRR("RAND_bytes failed"); close(fd_in); goto cleanup;
        }

        INFO("payload %zu/%zu: %s (%" PRIu64 " bytes)",
             p + 1, a->input_count, pl->name, pl->original_size);

        if (layout_payload(&cfg, pl->original_size, &res,
                           &pl->chunks, &pl->chunk_count) != 0) {
            close(fd_in); goto cleanup;
        }

        unsigned char key[KEY_LEN];
        if (derive_key(password, pl->salt, key) != 0) {
            close(fd_in); goto cleanup;
        }

        uint64_t read_off = 0;
        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            Chunk *c = &pl->chunks[i];
            uint32_t raw_len = c->length - GCM_TAG_LEN;

            unsigned char *pt = malloc(raw_len);
            unsigned char *ct = malloc(raw_len);
            unsigned char *block = malloc(c->length);
            if (!pt || !ct || !block) {
                ERRR("OOM");
                free(pt); free(ct); free(block);
                OPENSSL_cleanse(key, KEY_LEN);
                close(fd_in); goto cleanup;
            }

            if (pread_all(fd_in, pt, raw_len, (off_t)read_off) != 0) {
                ERRR("read payload %s at %" PRIu64 ": %s", path, read_off, strerror(errno));
                free(pt); free(ct); free(block);
                OPENSSL_cleanse(key, KEY_LEN);
                close(fd_in); goto cleanup;
            }

            unsigned char iv[GCM_IV_LEN];
            build_iv(pl->salt, c->id, iv);

            unsigned char tag[GCM_TAG_LEN];
            if (gcm_encrypt(pt, raw_len, key, iv, ct, tag) != 0) {
                free(pt); free(ct); free(block);
                OPENSSL_cleanse(key, KEY_LEN);
                close(fd_in); goto cleanup;
            }

            memcpy(block, ct, raw_len);
            memcpy(block + raw_len, tag, GCM_TAG_LEN);

            SHA256(block, c->length, c->sha256);

            if (pwrite_all(fd_cont, block, c->length, (off_t)c->offset) != 0) {
                ERRR("write container @0x%" PRIx64 ": %s", c->offset, strerror(errno));
                free(pt); free(ct); free(block);
                OPENSSL_cleanse(key, KEY_LEN);
                close(fd_in); goto cleanup;
            }

            OPENSSL_cleanse(pt, raw_len);
            free(pt); free(ct); free(block);
            read_off += raw_len;

            TRACE("wrote chunk %u @0x%" PRIx64 " (%u B)", c->id, c->offset, c->length);
        }

        OPENSSL_cleanse(key, KEY_LEN);
        close(fd_in);
        INFO("payload %s: %u chunks encrypted and scattered", pl->name, pl->chunk_count);
    }

    if (fsync(fd_cont) != 0) WARN("fsync container: %s", strerror(errno));
    close(fd_cont); fd_cont = -1;

    if (write_map_file(&mf, a->map_path) != 0) goto cleanup;
    if (a->ops_path) {
        if (write_ops_file(&mf, a->ops_path) != 0) goto cleanup;
    }

    INFO("pack: all payloads written, map saved.");
    rc = 0;

cleanup:
    if (fd_cont >= 0) close(fd_cont);
    reserv_free(&res);
    mapfile_free(&mf);
    return rc;
}

/**
 * ensure_dir - mkdir -p @path, ignoring EEXIST. Returns 0 on success.
 */
static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        ERRR("%s exists and is not a directory", path);
        return -1;
    }
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        ERRR("mkdir %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * action_unpack - read map, verify each chunk's SHA-256 (optional integrity
 * pre-check), decrypt chunks with AES-256-GCM, and reassemble each payload
 * into @output_dir/<name>.
 */
static int action_unpack(const Args *a, char *password) {
    INFO("unpack: map=%s container=%s output_dir=%s",
         a->map_path, a->container, a->output_dir);

    MapFile mf;
    if (load_any_map(a->map_path, &mf) != 0) return -1;

    if (ensure_dir(a->output_dir) != 0) { mapfile_free(&mf); return -1; }

    int fd_cont = open(a->container, O_RDONLY);
    if (fd_cont < 0) {
        ERRR("open container %s: %s", a->container, strerror(errno));
        mapfile_free(&mf); return -1;
    }
    uint64_t actual = get_target_size(fd_cont, a->container);
    if (actual < mf.container_size)
        WARN("container is smaller than recorded (%" PRIu64 " < %" PRIu64 ")",
             actual, mf.container_size);

    int overall_rc = 0;

    for (size_t p = 0; p < mf.payload_count; p++) {
        Payload *pl = &mf.payloads[p];
        if (a->only_name && strcmp(a->only_name, pl->name) != 0) {
            DEBUG("skipping payload %s (filter=%s)", pl->name, a->only_name);
            continue;
        }

        char out_path[PATH_MAX];
        if (snprintf(out_path, sizeof out_path, "%s/%s", a->output_dir, pl->name)
            >= (int)sizeof out_path) {
            ERRR("output path too long for %s", pl->name);
            overall_rc = -1; continue;
        }

        int fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd_out < 0) { ERRR("open %s: %s", out_path, strerror(errno)); overall_rc = -1; continue; }

        unsigned char key[KEY_LEN];
        if (derive_key(password, pl->salt, key) != 0) {
            close(fd_out); unlink(out_path); overall_rc = -1; continue;
        }

        INFO("restoring %s: %u chunks → %s", pl->name, pl->chunk_count, out_path);

        uint64_t write_off = 0;
        bool payload_ok = true;

        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            Chunk *c = &pl->chunks[i];
            uint32_t raw_len = c->length - GCM_TAG_LEN;

            unsigned char *block = malloc(c->length);
            unsigned char *pt    = malloc(raw_len);
            if (!block || !pt) {
                ERRR("OOM"); free(block); free(pt); payload_ok = false; break;
            }

            if (pread_all(fd_cont, block, c->length, (off_t)c->offset) != 0) {
                ERRR("read container @0x%" PRIx64 ": %s", c->offset, strerror(errno));
                free(block); free(pt); payload_ok = false; break;
            }

            /* Optional integrity gate: verify the recorded SHA-256 before
             * even attempting decryption. Gives a clearer error message when
             * the container has been physically altered. */
            unsigned char digest[32];
            SHA256(block, c->length, digest);
            if (memcmp(digest, c->sha256, 32) != 0) {
                ERRR("chunk %u of %s: SHA-256 mismatch — container corrupted or tampered",
                     c->id, pl->name);
                free(block); free(pt); payload_ok = false; break;
            }

            unsigned char iv[GCM_IV_LEN];
            build_iv(pl->salt, c->id, iv);

            int drc = gcm_decrypt(block, raw_len, block + raw_len, key, iv, pt);
            if (drc == -2) {
                ERRR("chunk %u of %s: GCM authentication failed (wrong password or tampering)",
                     c->id, pl->name);
                free(block); free(pt); payload_ok = false; break;
            } else if (drc != 0) {
                ERRR("chunk %u of %s: decryption error", c->id, pl->name);
                free(block); free(pt); payload_ok = false; break;
            }

            if (pwrite_all(fd_out, pt, raw_len, (off_t)write_off) != 0) {
                ERRR("write %s @%" PRIu64 ": %s", out_path, write_off, strerror(errno));
                OPENSSL_cleanse(pt, raw_len);
                free(block); free(pt); payload_ok = false; break;
            }
            write_off += raw_len;
            OPENSSL_cleanse(pt, raw_len);
            free(block); free(pt);
            TRACE("decrypted chunk %u of %s", c->id, pl->name);
        }

        OPENSSL_cleanse(key, KEY_LEN);

        if (payload_ok && write_off != pl->original_size) {
            ERRR("reassembled size %" PRIu64 " != recorded %" PRIu64 " for %s",
                 write_off, pl->original_size, pl->name);
            payload_ok = false;
        }

        if (fsync(fd_out) != 0) WARN("fsync %s: %s", out_path, strerror(errno));
        close(fd_out);

        if (!payload_ok) {
            unlink(out_path);
            overall_rc = -1;
            continue;
        }

        INFO("payload %s restored OK (%" PRIu64 " bytes)", pl->name, pl->original_size);
    }

    close(fd_cont);
    mapfile_free(&mf);
    return overall_rc;
}

/**
 * action_audit - sanity-check a map file and optionally cross-check chunk
 * SHA-256 against a container. Does NOT require a password.
 */
static int action_audit(const Args *a) {
    INFO("audit: map=%s container=%s", a->map_path, a->container ? a->container : "(none)");

    MapFile mf;
    if (load_any_map(a->map_path, &mf) != 0) return -1;

    INFO("map describes container '%s' (%" PRIu64 " bytes), %zu payload(s)",
         mf.container_path, mf.container_size, mf.payload_count);
    INFO("skip_head=%" PRIu64 " skip_tail=%" PRIu64, mf.skip_head, mf.skip_tail);

    int rc = 0;

    /* Bounds and overlap check across all chunks. */
    ReservList res = {0};
    for (size_t p = 0; p < mf.payload_count; p++) {
        Payload *pl = &mf.payloads[p];
        uint64_t sum = 0;
        for (uint32_t i = 0; i < pl->chunk_count; i++) {
            Chunk *c = &pl->chunks[i];
            if (c->offset < mf.skip_head) {
                ERRR("payload %s chunk %u: offset 0x%" PRIx64 " inside skip_head",
                     pl->name, c->id, c->offset); rc = -1;
            }
            if (c->offset + c->length > mf.container_size - mf.skip_tail) {
                ERRR("payload %s chunk %u: ends past container minus skip_tail",
                     pl->name, c->id); rc = -1;
            }
            if (reservation_overlaps(&res, c->offset, c->length, 0)) {
                ERRR("payload %s chunk %u: overlaps another chunk",
                     pl->name, c->id); rc = -1;
            }
            reserv_push(&res, c->offset, c->length);
            sum += (uint64_t)(c->length - GCM_TAG_LEN);
        }
        if (sum != pl->original_size) {
            ERRR("payload %s: chunks sum to %" PRIu64 ", original_size says %" PRIu64,
                 pl->name, sum, pl->original_size); rc = -1;
        } else {
            INFO("payload %s: topology OK (%u chunks, %" PRIu64 " bytes)",
                 pl->name, pl->chunk_count, sum);
        }
    }
    reserv_free(&res);

    /* Physical SHA-256 check if container provided. */
    const char *cont = a->container ? a->container : mf.container_path;
    int fd_cont = open(cont, O_RDONLY);
    if (fd_cont < 0) {
        WARN("cannot open container '%s' for physical check: %s", cont, strerror(errno));
    } else {
        uint64_t actual = get_target_size(fd_cont, cont);
        INFO("container physical size: %" PRIu64 " bytes", actual);
        if (actual < mf.container_size)
            ERRR("container has shrunk — data likely lost");

        size_t total_chunks = 0, good = 0, bad = 0;
        for (size_t p = 0; p < mf.payload_count; p++) total_chunks += mf.payloads[p].chunk_count;
        INFO("verifying SHA-256 of %zu chunks on disk...", total_chunks);

        for (size_t p = 0; p < mf.payload_count; p++) {
            Payload *pl = &mf.payloads[p];
            for (uint32_t i = 0; i < pl->chunk_count; i++) {
                Chunk *c = &pl->chunks[i];
                unsigned char *buf = malloc(c->length);
                if (!buf) { ERRR("OOM"); rc = -1; break; }
                if (pread_all(fd_cont, buf, c->length, (off_t)c->offset) != 0) {
                    ERRR("read @0x%" PRIx64 ": %s", c->offset, strerror(errno));
                    free(buf); bad++; rc = -1; continue;
                }
                unsigned char dg[32];
                SHA256(buf, c->length, dg);
                if (memcmp(dg, c->sha256, 32) == 0) good++; else { bad++; rc = -1;
                    WARN("sha256 mismatch: payload=%s chunk=%u off=0x%" PRIx64,
                         pl->name, c->id, c->offset);
                }
                free(buf);
            }
        }
        INFO("sha256 results: %zu OK, %zu BAD", good, bad);
        close(fd_cont);
    }

    mapfile_free(&mf);
    return rc;
}

/* ============================================================
 * CLI
 * ============================================================ */

static void print_help(const char *prog) {
    printf(
"scatter %s — plausible-deniability steganographic scatter tool\n"
"\n"
"USAGE\n"
"  %s pack    -c <cont> -m <map> [--ops <ops>] -p PASS|-P FILE [opts] -- <file> [file ...]\n"
"  %s unpack  -c <cont> -m <map-or-ops>          -p PASS|-P FILE [-O <outdir>] [-n <n>]\n"
"  %s audit   -m <map-or-ops> [-c <cont>]\n"
"\n"
"GLOBAL OPTIONS\n"
"  -v, --verbose             Increase log verbosity (repeatable: -v, -vv, -vvv)\n"
"  -q, --quiet               Warnings and errors only\n"
"      --no-color            Disable ANSI color in logs\n"
"  -h, --help                Show this help\n"
"  -V, --version             Show version\n"
"\n"
"PACK OPTIONS\n"
"  -c, --container PATH      Container (regular file or block device, pre-filled\n"
"                            with /dev/urandom — scatter does NOT fill it for you)\n"
"  -m, --map PATH            Rich human-readable map file (debug/audit view)\n"
"      --ops PATH            Optional: minimal machine-parseable ops file\n"
"  -p, --password PASS       Password on command line (WARNING: visible in ps)\n"
"  -P, --password-file FILE  Read password from FILE (first line, CRLF stripped)\n"
"      --skip-head N         Bytes to leave untouched at start (default %u)\n"
"      --skip-tail N         Bytes to leave untouched at end   (default %u)\n"
"      --min-chunk N         Min chunk size (default %u)\n"
"      --max-chunk N         Max chunk size (default %u)\n"
"      --min-gap N           Min gap between chunks (default %u)\n"
"      --max-gap N           Max gap between chunks (default %u)\n"
"\n"
"UNPACK OPTIONS\n"
"  -c, --container PATH      Container to read from\n"
"  -m, --map PATH            Map file OR ops file (auto-detected)\n"
"  -O, --output-dir DIR      Where to write restored payloads (default ./restored)\n"
"  -n, --name NAME           Only restore payload with this name\n"
"  -p, --password PASS       Password on command line\n"
"  -P, --password-file FILE  Read password from FILE\n"
"\n"
"PASSWORD NOTES\n"
"  - Passwords are raw bytes; any character allowed (quotes, $, spaces, UTF-8).\n"
"  - Shell escaping is YOUR job. In bash/zsh prefer single quotes:\n"
"      -p 'my$weird\"pa ss'       # no $/backtick/backslash expansion\n"
"  - -p is visible in /proc/<pid>/cmdline and shell history; prefer -P:\n"
"      umask 077 && printf %%s 'mySecret' > /run/user/$UID/p\n"
"      scatter pack -P /run/user/$UID/p ... && shred -u /run/user/$UID/p\n"
"\n"
"EXAMPLES\n"
"  sudo dd if=/dev/urandom of=/dev/sdb bs=4M status=progress    # 1. prefill\n"
"  %s pack   -c /dev/sdb -m sdb.map --ops sdb.ops -P pw -- a.zip b.txt\n"
"  %s audit  -m sdb.map -c /dev/sdb\n"
"  %s unpack -c /dev/sdb -m sdb.ops -O ./restored -P pw\n"
"\n",
        SCATTER_VERSION, prog, prog, prog,
        DEFAULT_SKIP_HEAD, DEFAULT_SKIP_TAIL,
        DEFAULT_MIN_CHUNK, DEFAULT_MAX_CHUNK,
        DEFAULT_MIN_GAP,   DEFAULT_MAX_GAP,
        prog, prog, prog);
}

enum { MODE_NONE, MODE_PACK, MODE_UNPACK, MODE_AUDIT };

/* Long-option identifiers above the ASCII range. */
enum {
    OPT_SKIP_HEAD = 0x1000,
    OPT_SKIP_TAIL,
    OPT_MIN_CHUNK,
    OPT_MAX_CHUNK,
    OPT_MIN_GAP,
    OPT_MAX_GAP,
    OPT_NO_COLOR,
    OPT_OPS,
};

int main(int argc, char **argv) {
    if (argc < 2) { print_help(argv[0]); return 2; }

    int mode = MODE_NONE;
    if      (!strcmp(argv[1], "pack"))    mode = MODE_PACK;
    else if (!strcmp(argv[1], "unpack"))  mode = MODE_UNPACK;
    else if (!strcmp(argv[1], "audit"))   mode = MODE_AUDIT;
    else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) { print_help(argv[0]); return 0; }
    else if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
        printf("scatter %s\n", SCATTER_VERSION); return 0;
    } else {
        ERRR("unknown subcommand: %s", argv[1]);
        print_help(argv[0]); return 2;
    }

    /* Shift argv so getopt sees the subcommand as argv[0]. */
    argv[1] = argv[0];
    argc--; argv++;

    Args a = {
        .log_level = LOG_INFO,
        .skip_head = DEFAULT_SKIP_HEAD,
        .skip_tail = DEFAULT_SKIP_TAIL,
        .min_chunk = DEFAULT_MIN_CHUNK,
        .max_chunk = DEFAULT_MAX_CHUNK,
        .min_gap   = DEFAULT_MIN_GAP,
        .max_gap   = DEFAULT_MAX_GAP,
        .output_dir = "./restored",
    };

    const char *password_file = NULL;

    static const struct option longopts[] = {
        {"verbose",       no_argument,       0, 'v'},
        {"quiet",         no_argument,       0, 'q'},
        {"no-color",      no_argument,       0, OPT_NO_COLOR},
        {"help",          no_argument,       0, 'h'},
        {"version",       no_argument,       0, 'V'},
        {"container",     required_argument, 0, 'c'},
        {"map",           required_argument, 0, 'm'},
        {"ops",           required_argument, 0, OPT_OPS},
        {"password",      required_argument, 0, 'p'},
        {"password-file", required_argument, 0, 'P'},
        {"output-dir",    required_argument, 0, 'O'},
        {"name",          required_argument, 0, 'n'},
        {"skip-head",     required_argument, 0, OPT_SKIP_HEAD},
        {"skip-tail",     required_argument, 0, OPT_SKIP_TAIL},
        {"min-chunk",     required_argument, 0, OPT_MIN_CHUNK},
        {"max-chunk",     required_argument, 0, OPT_MAX_CHUNK},
        {"min-gap",       required_argument, 0, OPT_MIN_GAP},
        {"max-gap",       required_argument, 0, OPT_MAX_GAP},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "vqhVc:m:p:P:O:n:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'v':
            if (g_log_level > LOG_TRACE) g_log_level--;
            break;
        case 'q': g_log_level = LOG_WARN; break;
        case OPT_NO_COLOR: g_log_color = false; break;
        case 'h': print_help(argv[0]); return 0;
        case 'V': printf("scatter %s\n", SCATTER_VERSION); return 0;
        case 'c': a.container    = optarg; break;
        case 'm': a.map_path     = optarg; break;
        case OPT_OPS: a.ops_path = optarg; break;
        case 'p': a.password_cli = optarg; break;
        case 'P': password_file  = optarg; break;
        case 'O': a.output_dir   = optarg; break;
        case 'n': a.only_name    = optarg; break;
        case OPT_SKIP_HEAD: a.skip_head = strtoull(optarg, NULL, 0); break;
        case OPT_SKIP_TAIL: a.skip_tail = strtoull(optarg, NULL, 0); break;
        case OPT_MIN_CHUNK: a.min_chunk = (uint32_t)strtoul(optarg, NULL, 0); break;
        case OPT_MAX_CHUNK: a.max_chunk = (uint32_t)strtoul(optarg, NULL, 0); break;
        case OPT_MIN_GAP:   a.min_gap   = (uint32_t)strtoul(optarg, NULL, 0); break;
        case OPT_MAX_GAP:   a.max_gap   = (uint32_t)strtoul(optarg, NULL, 0); break;
        default: print_help(argv[0]); return 2;
        }
    }

    /* Positional args = input files (pack only). */
    if (optind < argc) {
        a.input_count = (size_t)(argc - optind);
        a.input_files = (const char **)&argv[optind];
    }

    /* Validate per-mode. */
    if (!a.map_path) FATAL("missing -m/--map");
    if (mode == MODE_PACK || mode == MODE_UNPACK) {
        if (!a.container) FATAL("missing -c/--container");
    }
    if (mode == MODE_PACK) {
        if (a.input_count == 0) FATAL("pack: need at least one input file");
        if (a.min_chunk < 1)    FATAL("min-chunk must be >= 1");
        if (a.max_chunk < a.min_chunk) FATAL("max-chunk < min-chunk");
        if (a.max_chunk > HARD_MAX_CHUNK) FATAL("max-chunk too large (hard limit %u)", HARD_MAX_CHUNK);
        if (a.min_gap > a.max_gap) FATAL("min-gap > max-gap");
    }

    /* Password: exactly one of -p/-P must be supplied for pack/unpack.
     * No interactive prompt — this build is non-interactive by design. */
    char *password = NULL;
    if (mode == MODE_PACK || mode == MODE_UNPACK) {
        if (a.password_cli && password_file) FATAL("use either -p or -P, not both");
        if (!a.password_cli && !password_file) FATAL("missing password (-p PASS or -P FILE)");

        if (a.password_cli) {
            password = strdup(a.password_cli);
            if (!password) FATAL("OOM");
            /* Best-effort wipe of argv copy. A determined attacker with
             * /proc access will still see it before we reach here — always
             * prefer -P for real secrets. */
            memset((void *)a.password_cli, 0, strlen(a.password_cli));
        } else {
            password = read_password_file(password_file);
            if (!password) FATAL("could not read password from file");
        }
        if (strlen(password) == 0) {
            free(password);
            FATAL("empty password");
        }
    }

    int rc = 0;
    switch (mode) {
    case MODE_PACK:   rc = action_pack(&a, password);   break;
    case MODE_UNPACK: rc = action_unpack(&a, password); break;
    case MODE_AUDIT:  rc = action_audit(&a);            break;
    }

    if (password) {
        OPENSSL_cleanse(password, strlen(password));
        free(password);
    }

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
