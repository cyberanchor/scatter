<div align="center">

```
                                                                     
                                 _|      _|                          
   _|_|_|    _|_|_|    _|_|_|  _|_|_|_|_|_|_|_|    _|_|    _|  _|_|  
 _|_|      _|        _|    _|    _|      _|      _|_|_|_|  _|_|      
     _|_|  _|        _|    _|    _|      _|      _|        _|        
 _|_|_|      _|_|_|    _|_|_|      _|_|    _|_|    _|_|_|  _|        
                                                                     
                                                                                            
```

**Just For Fun! Plausible-deniability steganographic scatter tool**<br>
*AES-256-GCM | PBKDF2-HMAC-SHA256*

<br>

![Version](https://img.shields.io/badge/version-2.1.0-blue?style=flat-square)
<br>

</div>

`scatter` takes one or more files, encrypts each with AES-256-GCM, splits
the ciphertext into variable-length fragments, and hides those fragments
at pseudo-random offsets inside a larger container — typically a USB
stick or disk image pre-filled with `/dev/urandom`.

---

## Features

- **AES-256-GCM** per-chunk encryption, 128-bit authentication tag.
- **PBKDF2-HMAC-SHA256**, 600 000 iterations, per-payload 128-bit salt.
- **Multiple payloads per container**, non-overlapping, each with its own salt.
- **Configurable** chunk size, gap size, and head/tail skip zones.
- **Plain-text map** (`0x00ab34...` offsets, chunk lengths, SHA-256 per chunk).
- **Minimal ops file** — trivial one-letter-per-record format for custom tooling.
- **Audit mode** — re-verify SHA-256 of every chunk on disk without the password.
- **Block devices** and regular files supported.
- **Static musl build** with zero runtime dependencies.
- **Non-interactive**: password via `-p STRING` or `-P FILE`, no TTY prompt.

---

## Build

### Requirements

- C11 compiler (`gcc` ≥ 9 or `clang` ≥ 10)
- OpenSSL ≥ 1.1 (headers + libcrypto)
- GNU Make
- Linux 2.6+ (uses `BLKGETSIZE64`; a fallback is provided so
  `linux/fs.h` / kernel-headers are *not* required for musl builds)

### Dynamic (release)

```bash
make
sudo make install          # /usr/local/bin/scatter
```

Produces a stripped, hardened PIE with no BuildID note.

### Static musl (zero runtime deps)

One-time: build a static OpenSSL under `/usr/local/musl`:

```bash
curl -LO https://www.openssl.org/source/openssl-3.3.1.tar.gz
tar xf openssl-3.3.1.tar.gz && cd openssl-3.3.1
CC=musl-gcc ./Configure linux-x86_64 no-shared no-async no-engine \
    --prefix=/usr/local/musl
make -j && sudo make install_sw
```

Then:

```bash
make static-musl
file scatter-static
# scatter-static: ELF 64-bit LSB executable, statically linked, stripped
```

### Debug build (ASan + UBSan)

```bash
make debug
./scatter-debug pack ...
```

---

## Quick start

```bash
# 1. Fill the container with random bytes (once, by you — scatter won't do it).
sudo dd if=/dev/urandom of=/dev/sdb bs=4M status=progress

# 2. Store the password on tmpfs.
umask 077
printf '%s' 'correct horse battery staple' > /run/user/$UID/pw

# 3. Pack three files onto the USB stick.
scatter pack \
    -c /dev/sdb \
    -m sdb.map          \
    --ops sdb.ops        \
    -P /run/user/$UID/pw \
    -- secret.zip notes.md photo.jpg

# 4. Verify integrity any time later (no password needed).
scatter audit -m sdb.map -c /dev/sdb

# 5. Restore.
scatter unpack -c /dev/sdb -m sdb.ops -O ./restored -P /run/user/$UID/pw

# 6. Wipe the on-disk password.
shred -u /run/user/$UID/pw
```

---

## Command reference

### `pack`

Encrypt the given files and scatter them across the container.

```
scatter pack  -c CONTAINER  -m MAP  [--ops OPS]  -p PASS | -P FILE
              [--skip-head N] [--skip-tail N]
              [--min-chunk N] [--max-chunk N]
              [--min-gap N]   [--max-gap N]
              -- FILE [FILE ...]
```

| Flag | Default | Purpose |
|---|---|---|
| `-c, --container` |  | Target (regular file or block device) |
| `-m, --map`       |  | Rich, human-readable map file |
| `--ops`           |  | Optional minimal ops file for production decoders |
| `-p, --password`  |  | Password literal (visible in `ps`) |
| `-P, --password-file` |  | Read password from a file (first line, CRLF stripped) |
| `--skip-head`     | 10    | Bytes to leave untouched at start of container |
| `--skip-tail`     | 10    | Bytes to leave untouched at end of container |
| `--min-chunk`     | 4096  | Minimum chunk (plaintext) size |
| `--max-chunk`     | 262144| Maximum chunk size |
| `--min-gap`       | 4096  | Minimum inter-chunk gap |
| `--max-gap`       | 65536 | Maximum inter-chunk gap |

### `unpack`

```
scatter unpack  -c CONTAINER  -m MAP|OPS  -p PASS | -P FILE
                [-O DIR]  [-n NAME]
```

`-m` accepts either a map file or an ops file — scatter auto-detects.

### `audit`

```
scatter audit  -m MAP|OPS  [-c CONTAINER]
```

Verifies chunk topology and (if `-c` is given) SHA-256 of every chunk on
the container. No password required.

---

## Password handling & shell escaping

Passwords are passed to PBKDF2 as raw bytes. Scatter does not escape,
normalize, or trim anything — except that the *file* form strips a
trailing `\r\n` from the first line.

| Method | Visible to other users? | Notes |
|---|---|---|
| `-p 'literal'`  | **Yes** — `/proc/<pid>/cmdline`, shell history | Fine for scripts and testing |
| `-P file`       | Only if file is readable  | **Preferred**; put on tmpfs, `shred` after |

Shell quoting rules (your shell, not scatter):

```bash
# Safe — literal, no expansion:
scatter pack -p 'my$weird"pa ss' ...

# Dangerous — $, `, \, ! still expand in double quotes:
scatter pack -p "my$weird"       ...     # $weird expands!

# Literal single quote:
scatter pack -p 'it'\''s fine'   ...

# Completely shell-agnostic:
printf '%s' 'any "$bytes" are fine' > pw
scatter pack -P pw ...
```

The integration test (`test_scatter.sh`) round-trips passwords
containing `$`, `'`, `"`, space, backtick, backslash, `!`, UTF-8
(`пароль-日本語-🔑`), and embedded `\t` / `\n` / `\x01` — all pass.

---

## File formats

### Map file (human-readable)

```text
# scatter map v2 — human-readable layout & audit file
# generated by: scatter 2.1.0 (OpenSSL 3.0.13 ...)
format_version=2
tool_version=2.1.0
container=/dev/sdb
container_size=8053063680
skip_head=10
skip_tail=10
created=2026-04-17T14:24:56Z

# -- aggregate statistics (informational, not parsed on read) --
# payload_count=3
# total_chunks=63
# total_plaintext_bytes=1114590
# total_ciphertext_bytes=1115598
# container_usage=0.014%
# earliest_offset=0x0000153f5e
# latest_end=0x000003d16bfb

# ------------------------------------------------------------
# payload 1 / 3: secret.zip
# ------------------------------------------------------------
[payload]
name=secret.zip
original_size=1048576
salt=77d3f2df6295e2a8ea7f97ba7005ffc0
pbkdf2_iterations=600000
cipher=aes-256-gcm
iv_scheme=salt8_be_chunkid4
chunk_count=57
# min_plaintext_chunk=4096
# max_plaintext_chunk=32768
# id        offset        length   sha256(ciphertext||tag)
00000000  0x0002dc320d  00011242 e6b6db8ae0c40371c5886236f4b36def40648cc26a123ae55b49342588cbbdf3
00000001  0x000371fedc  00009039 193fb37f41a2c08315e2efbc836dee4da8f65750160c5f95bc0e11d45438a671
...
# end of payload secret.zip (57 chunks)
```

### Ops file (machine-parseable)

One record per line: `<tag> <value>`.

```text
# scatter ops v1
V 1
C /dev/sdb
S 8053063680
H 10
T 10
P secret.zip
N 1048576
K 77d3f2df6295e2a8ea7f97ba7005ffc0
I 600000
O 0x0002dc320d
L 11242
D e6b6db8ae0c40371c5886236f4b36def40648cc26a123ae55b49342588cbbdf3
O 0x000371fedc
L 9039
D 193fb37f41a2c08315e2efbc836dee4da8f65750160c5f95bc0e11d45438a671
...
E secret.zip
```

Tags: `V`ersion, `C`ontainer, `S`ize, skip-`H`ead, skip-`T`ail,
`P`ayload-begin, `N`ame-size, salt (`K`ey-material),
`I`terations, `O`ffset, `L`ength, `D`igest, `E`nd-payload.


---

## Cryptographic details

| Item | Value |
|---|---|
| KDF            | PBKDF2-HMAC-SHA256, 600 000 iterations |
| Salt           | 16 random bytes per payload (not per run) |
| Key            | 256 bits, unique per payload |
| Cipher         | AES-256-GCM |
| IV             | 96 bits = `salt[0..7] ‖ be32(chunk_id)` |
| Tag            | 128 bits, appended to ciphertext |
| Integrity note | SHA-256 over `ciphertext ‖ tag`, recorded in map/ops |

**IV uniqueness.** Within one payload, `chunk_id` is unique. Across
payloads sharing a password, the *key* differs (different salt), so
identical `(salt_prefix, chunk_id)` pairs are not a reuse in the
cryptographic sense.

---

## Threat model

| Adversary capability | Protected? |
|---|---|
| Sees only the container, no map, no password | ✅ Ciphertext indistinguishable from pre-filled urandom |
| Has the map/ops file but not the password    | Partial — must brute-force PBKDF2; use a strong password |
| Has the password but not the map             | Must scan the whole container for GCM-valid frames; costly but not impossible |
| Has both                                     | ❌ Everything recoverable (by design) |
| Physically tampered with the container       | ✅ Detected by `audit` via SHA-256 |
| Coercion ("decrypt or else")                 | ❌ Not deniable encryption; just obscurity |

Keep the map/ops file **physically separate** from the container.

---

## Limitations and design notes

- scatter does **not** wipe/fill the container. Do it once with `dd`.
- One container ↔ one map. Running `pack` twice on the same container
  with two different maps will overwrite chunks from the first pack.
  (An `--append-to=old.map` mode is a possible future addition.)
- No TTY password prompt — use `-p` or `-P`. This is intentional for
  scripting/automation.
- Container must hold a few ×  payload size to find non-overlapping
  slots with gaps. A 1 MiB payload in a 2 MiB container will likely
  abort with "container too small or fragmented".
- Max chunk size is capped at 16 MiB by `HARD_MAX_CHUNK`.

---

## Testing

```bash
make test
```

Runs `test_scatter.sh`, which packs three payloads (1 MiB / 66 KB / 14 B),
audits and unpacks via both map and ops, verifies tamper detection,
wrong-password rejection, dual-password-flag rejection, and eight
special-character password round-trips.

AddressSanitizer / UndefinedBehaviorSanitizer:

```bash
make debug
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
    ./scatter-debug pack -c cont -m map -P pw -- file1 file2
```
