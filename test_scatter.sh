#!/usr/bin/env bash
# ============================================================
# test_scatter.sh — integration self-test for scatter 2.1.x
# ============================================================

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
bin="$here/scatter"
work=$(mktemp -d -t scatter-test.XXXXXX)
trap 'rm -rf "$work"' EXIT

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
hdr()   { printf "\n\033[1;36m== %s ==\033[0m\n" "$*"; }

hdr "Preparing 64 MiB container of urandom"
cont="$work/container.bin"
dd if=/dev/urandom of="$cont" bs=1M count=64 status=none

hdr "Preparing payloads (1 MiB, 66 KB, 14 B)"
dd if=/dev/urandom of="$work/secret.zip" bs=1M count=1 status=none
dd if=/dev/urandom of="$work/notes.txt"  bs=1   count=66000 status=none
printf "hello scatter\n" > "$work/hi.txt"

hdr "Pack (writes both map and ops, password from -P file)"
pw_file="$work/password.txt"
umask 077; printf 'correcthorsebatterystaple' > "$pw_file"
"$bin" pack \
    -c "$cont" \
    -m "$work/container.map" \
    --ops "$work/container.ops" \
    -P "$pw_file" \
    --min-chunk 4096 --max-chunk 32768 \
    --min-gap 1024  --max-gap 8192 \
    -- "$work/secret.zip" "$work/notes.txt" "$work/hi.txt"

hdr "Map file (first 25 lines)"
head -25 "$work/container.map"

hdr "Ops file (first 15 lines)"
head -15 "$work/container.ops"

hdr "Audit via MAP"
"$bin" audit -m "$work/container.map" -c "$cont"

hdr "Audit via OPS"
"$bin" audit -m "$work/container.ops" -c "$cont"

hdr "Unpack via MAP"
mkdir -p "$work/rest_map"
"$bin" unpack -c "$cont" -m "$work/container.map" -O "$work/rest_map" -P "$pw_file"

hdr "Unpack via OPS"
mkdir -p "$work/rest_ops"
"$bin" unpack -c "$cont" -m "$work/container.ops" -O "$work/rest_ops" -P "$pw_file"

hdr "Compare hashes (both paths)"
for tag in rest_map rest_ops; do
    for f in secret.zip notes.txt hi.txt; do
        a=$(sha256sum "$work/$f"       | awk '{print $1}')
        b=$(sha256sum "$work/$tag/$f"  | awk '{print $1}')
        if [[ "$a" == "$b" ]]; then green "  OK  $tag/$f"; else
            red "  BAD $tag/$f  $a vs $b"; exit 1; fi
    done
done

hdr "Negative: wrong password"
printf 'wrongpass' > "$work/wrong.pw"
set +e
"$bin" unpack -c "$cont" -m "$work/container.map" -O "$work/rest_bad" -P "$work/wrong.pw" --no-color >"$work/bad.log" 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "GCM authentication failed" "$work/bad.log"; then
    green "OK: wrong password rejected (exit=$rc)"
else
    red "FAIL: wrong password did not fail cleanly (exit=$rc)"; cat "$work/bad.log"; exit 1
fi

hdr "Negative: tamper one byte in container, audit must catch it"
first_off=$(awk '/^[0-9]{8} +0x/{print $2; exit}' "$work/container.map")
first_off_dec=$(printf "%d" "$first_off")
printf '\xFF' | dd of="$cont" bs=1 count=1 seek=$((first_off_dec + 100)) conv=notrunc status=none
set +e
audit_out=$("$bin" audit --no-color -m "$work/container.map" -c "$cont" 2>&1)
set -e
if printf "%s" "$audit_out" | grep -qE "sha256 mismatch|[1-9][0-9]* BAD"; then
    green "OK: audit detected tampering"
else
    red "FAIL: audit did not detect tampering"; printf "%s\n" "$audit_out"; exit 1
fi

# ------------------------------------------------------------
# Password special-character tests
# ------------------------------------------------------------
hdr "Special-char passwords (via -P so shell escaping is irrelevant)"

test_special_pw() {
    local label="$1"; local pw="$2"
    local tcont="$work/c_$label.bin"
    local tpw="$work/pw_$label.txt"
    dd if=/dev/urandom of="$tcont" bs=1M count=4 status=none
    printf '%s' "$pw" > "$tpw"
    printf 'test payload for %s\n' "$label" > "$work/p_$label.txt"

    "$bin" pack  -c "$tcont" -m "$work/m_$label" -P "$tpw" --no-color \
        --min-chunk 4096 --max-chunk 8192 --min-gap 512 --max-gap 2048 \
        -- "$work/p_$label.txt" >/dev/null
    mkdir -p "$work/r_$label"
    "$bin" unpack -c "$tcont" -m "$work/m_$label" -O "$work/r_$label" -P "$tpw" --no-color >/dev/null

    if cmp -s "$work/p_$label.txt" "$work/r_$label/p_$label.txt"; then
        green "  OK  $label  (pw=$(printf '%s' "$pw" | od -An -c | tr -s ' ' | head -c 60))"
    else
        red   "  BAD $label"; exit 1
    fi
}

test_special_pw "dollar"   'my$weird$pa$$'
test_special_pw "quotes"   "quote'double\"both"
test_special_pw "space"    'pa ss with spa ces'
test_special_pw "backtick" 'pa`rm-rf /`word'
test_special_pw "backslash" 'back\\slash\\pw'
test_special_pw "bang"     'history!event!'
test_special_pw "utf8"     'пароль-日本語-🔑'
test_special_pw "control"  $'tab\there\nand\x01bell'

# ------------------------------------------------------------
hdr "Negative: -p and -P both supplied → refuse"
set +e
"$bin" pack -c "$work/container.bin" -m /tmp/x.map \
    -p abc -P "$pw_file" --no-color \
    -- "$work/hi.txt" 2>"$work/dual.log" >/dev/null
rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "either -p or -P" "$work/dual.log"; then
    green "OK: -p + -P combination rejected"
else
    red "FAIL: dual password args not rejected"; cat "$work/dual.log"; exit 1
fi

hdr "All tests passed ✓"
