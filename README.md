<div align="center">

```
                                                                     
                                 _|      _|                          
   _|_|_|    _|_|_|    _|_|_|  _|_|_|_|_|_|_|_|    _|_|    _|  _|_|  
 _|_|      _|        _|    _|    _|      _|      _|_|_|_|  _|_|      
     _|_|  _|        _|    _|    _|      _|      _|        _|        
 _|_|_|      _|_|_|    _|_|_|      _|_|    _|_|    _|_|_|  _|        
                                                                     
```

**Just For Fun! Plausible-deniability steganographic scatter tool**<br>
*AES-256-GCM per-chunk | PBKDF2-HMAC-SHA256 | scattered placement in pre-randomized containers*

<br>

![Version](https://img.shields.io/badge/version-2.1.0-blue?style=flat-square)
![C](https://img.shields.io/badge/C-11-A8B9CC?style=flat-square&logo=c&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
![Arch](https://img.shields.io/badge/arch-amd64-orange?style=flat-square)
![Cipher](https://img.shields.io/badge/cipher-AES--256--GCM-blueviolet?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-PBKDF2-red?style=flat-square)
![Build](https://img.shields.io/badge/build-static%20musl-informational?style=flat-square)

<br>

[installation](#installation) •
[usage](#usage) •
[cryptographic architecture](#cryptographic-architecture) •
[file formats](#file-formats) •
[all flags](#all-flags) •
[threat model](#threat-model)

</div>

`scatter` takes one or more files, encrypts each with **AES-256-GCM**, splits
the ciphertext into variable-length fragments, and hides those fragments at
pseudo-random offsets inside a larger container — typically a USB stick or
disk image pre-filled with `/dev/urandom`. If the container was pre-randomized,
the encrypted fragments are indistinguishable from the surrounding noise
without the map/ops file **and** the password.

-----

## Cryptographic architecture

```text
Password
    │
    ▼
┌─────────────────────────────────────────────┐
│  PBKDF2-HMAC-SHA256 (600 000 iterations)   │
│  salt: 16 random bytes PER PAYLOAD          │
└──────────────┬──────────────────────────────┘
               │ 256-bit key (unique per payload)
               ▼
       ┌───────┴────────┐
       │  AES-256-GCM    │
       │  IV = salt[0..7] ‖ be32(chunk_id)
       └───────┬────────┘
               │
    ┌──────────┼──────────┬──────────┐
    ▼          ▼          ▼          ▼
 chunk 0    chunk 1    chunk 2    chunk N     ← variable length [min..max]
 + tag 16B  + tag 16B  + tag 16B  + tag 16B
    │          │          │          │
    ▼          ▼          ▼          ▼
 ┌────────────────────────────────────┐
 │  scattered into the container      │
 │  at pseudo-random offsets,         │
 │  non-overlapping, random gaps,     │
 │  skipping head/tail zones          │
 └────────────────────────────────────┘
```

### Per-chunk flow

Each chunk is encrypted with a unique 96-bit IV derived from the payload's
random salt and the chunk's sequential ID, so IVs never repeat within a payload
and never collide across payloads (different salt → different key). The 128-bit
GCM tag is appended and the whole `ciphertext‖tag` block is fingerprinted with
SHA-256, which is recorded in the map for password-less integrity auditing.

### Layout engine

Chunk lengths are uniformly sampled from `[min_chunk, max_chunk]` with
rejection sampling (no modulo bias). Placement is random-with-retry inside
`[skip_head, container_size - skip_tail]`, rejecting any candidate whose
expansion by `[min_gap, max_gap]` overlaps an existing reservation. Chunks
from different payloads share the same reservation list, so they cannot
collide either.

### Why it looks like noise

AES-GCM ciphertext + tag is the output of a PRF keyed by a secret. Without the
key it is statistically indistinguishable from uniform random bytes — Shannon
entropy, χ², NIST SP 800-22 all agree. No magic bytes, no headers, no padding
are written into the container.

## Installation

### From source (dynamic, system OpenSSL)

```bash
git clone https://github.com/cyberanchor/scatter
cd scatter
make
sudo make install          # → /usr/local/bin/scatter
```

Produces a **stripped, hardened PIE with no BuildID note**.

### Static musl build (zero runtime deps)

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

Kernel headers are **not required** — `scatter` provides a fallback
`BLKGETSIZE64` definition so musl builds work out of the box.

### Debug build (ASan + UBSan)

```bash
make debug
./scatter-debug pack ...
```

### Make targets

| Target | Description |
|---|---|
| `make` | Release build (dynamic, stripped, no BuildID) |
| `make static-musl` | Fully static musl binary, zero runtime deps |
| `make debug` | ASan + UBSan instrumented build |
| `make test` | Run integration self-test |
| `make dist` | Produce `scatter-$(VERSION).tar.gz` |
| `make install` | Install to `$(PREFIX)/bin` |
| `make clean` | Remove build artifacts |

## Usage

### Prepare the container (one-time)

```bash
sudo dd if=/dev/urandom of=/dev/sdb bs=4M status=progress
```

`scatter` does **not** fill the container for you — by design.

### Pack files into a container

```bash
umask 077
printf '%s' 'correct horse battery staple' > /run/user/$UID/pw

scatter pack \
    -c /dev/sdb           \
    -m sdb.map            \
    --ops sdb.ops         \
    -P /run/user/$UID/pw  \
    -- secret.zip notes.md photo.jpg

shred -u /run/user/$UID/pw
```

### Audit a container (no password needed)

```bash
scatter audit -m sdb.map -c /dev/sdb
```

### Restore payloads

```bash
scatter unpack -c /dev/sdb -m sdb.ops -O ./restored -P /run/user/$UID/pw
```

### Restore just one payload

```bash
scatter unpack -c /dev/sdb -m sdb.ops -O ./restored -P pw -n secret.zip
```

## File formats

### Map file — human-readable layout & audit view

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

# -- aggregate statistics --
# payload_count=3
# total_chunks=63
# container_usage=0.014%

[payload]
name=secret.zip
original_size=1048576
salt=77d3f2df6295e2a8ea7f97ba7005ffc0
pbkdf2_iterations=600000
cipher=aes-256-gcm
iv_scheme=salt8_be_chunkid4
chunk_count=57
# id        offset        length   sha256(ciphertext||tag)
00000000  0x0002dc320d  00011242 e6b6db8ae0c40371c5886236f4b36def40648cc26a123ae55b49342588cbbdf3
00000001  0x000371fedc  00009039 193fb37f41a2c08315e2efbc836dee4da8f65750160c5f95bc0e11d45438a671
# end of payload secret.zip (57 chunks)
```

### Ops file — minimal machine-parseable

One record per line, `<tag> <value>`. Trivial to parse from any language.

```text
V 1                ← format version
C /dev/sdb         ← container path
S 8053063680       ← container size
H 10               ← skip head
T 10               ← skip tail
P secret.zip       ← payload begin
N 1048576          ← original size
K 77d3f2df...      ← salt (16 bytes hex)
I 600000           ← PBKDF2 iterations
O 0x0002dc320d     ← chunk offset
L 11242            ← chunk length
D e6b6db8a...      ← sha256 of ciphertext‖tag
E secret.zip       ← payload end
```

`unpack` and `audit` auto-detect map vs ops format — use whichever you prefer.

## Password handling

Passwords are passed to PBKDF2 as raw bytes. `scatter` does no escaping or
normalization — shell quoting is your responsibility.

| Method | Visible to other users? | Notes |
|---|---|---|
| `-p 'literal'` | **Yes** — via `/proc/<pid>/cmdline`, shell history | Fine for scripts/testing |
| `-P file` | Only if file is readable | **Preferred**; put on tmpfs, `shred` after |

```bash
# Safe — single quotes, no expansion:
scatter pack -p 'my$weird"pa ss' ...

# Shell-agnostic — use -P:
printf '%s' 'any "$bytes" are fine' > pw
scatter pack -P pw ...
```

The integration test round-trips passwords containing `$`, `'`, `"`, space,
backtick, backslash, `!`, UTF-8 (`пароль-日本語-🔑`), and embedded
`\t` / `\n` / `\x01` — all pass.

## All flags

| Flag | Mode | Description |
|---|---|---|
| `pack` | — | Encrypt files and scatter into a container |
| `unpack` | — | Decrypt and restore payloads |
| `audit` | — | Verify topology and SHA-256 of chunks on disk |
| `-c, --container PATH` | pack/unpack | Container file or block device |
| `-m, --map PATH` | all | Map file (pack writes, unpack/audit read) |
| `--ops PATH` | pack | Also emit a machine-parseable ops file |
| `-p, --password PASS` | pack/unpack | Password literal (visible in `ps`) |
| `-P, --password-file FILE` | pack/unpack | Read password from file |
| `-O, --output-dir DIR` | unpack | Where to write restored payloads |
| `-n, --name NAME` | unpack | Only restore payload with this name |
| `--skip-head N` | pack | Bytes to leave untouched at start (default 10) |
| `--skip-tail N` | pack | Bytes to leave untouched at end (default 10) |
| `--min-chunk N` | pack | Min chunk size (default 4096) |
| `--max-chunk N` | pack | Max chunk size (default 262144) |
| `--min-gap N` | pack | Min inter-chunk gap (default 4096) |
| `--max-gap N` | pack | Max inter-chunk gap (default 65536) |
| `-v, --verbose` | all | Increase log verbosity (repeatable) |
| `-q, --quiet` | all | Warnings and errors only |
| `--no-color` | all | Disable ANSI colors |
| `-h, --help` | — | Show help |
| `-V, --version` | — | Show version |

## Threat model

| Adversary capability | Protected? |
|---|---|
| Sees only the container, no map, no password | ✅ Ciphertext indistinguishable from pre-filled urandom |
| Has the map/ops file but not the password | Partial — must brute-force PBKDF2; use a strong password |
| Has the password but not the map | Must scan the whole container for GCM-valid frames; costly but not impossible |
| Has both | ❌ Everything recoverable (by design) |
| Physically tampered with the container | ✅ Detected by `audit` via SHA-256 |
| Coercion ("decrypt or else") | ❌ Not deniable encryption; just obscurity |

Keep the map/ops file **physically separate** from the container.

## Limitations

- `scatter` does **not** wipe/fill the container. Do it once with `dd`.
- One container ↔ one map. Running `pack` twice on the same container with
  two different maps will overwrite chunks from the first pack.
- No TTY password prompt — use `-p` or `-P`. This is intentional for
  scripting and automation.
- Container must hold a few × payload size to find non-overlapping slots with
  gaps. A 1 MiB payload in a 2 MiB container will likely abort with
  "container too small or fragmented".
- Max chunk size is capped at 16 MiB.

## Disclaimer

`scatter` is intended exclusively for personal, lawful use. The author is
not responsible for any misuse of this software.
