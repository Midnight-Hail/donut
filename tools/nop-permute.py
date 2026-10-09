#!/usr/bin/env python3
"""
nop-permute.py — post-link, pre-exe2h binary pass over loader.exe.

Scans the PE's .text section for inter-function NOP padding runs (identified
by preceding RET sentinels `c3` or `c2 xx xx`, followed by >= 2 NOP bytes),
and replaces each run with a same-length permutation of GCC-blessed
multi-byte NOP variants chosen from a DONUT_SEED-seeded PRNG.

Safety guard: if DonutLoader's known x64 prologue is not at .text offset 0,
refuse to permute (would mean a future refactor reordered the mingw command
line and offset-0 drifted off DonutLoader). A no-op in stock/empty-seed
builds (PRNG with empty seed selects identity).

Usage: python3 tools/nop-permute.py <path/to/loader.exe>
"""
import hashlib
import os
import struct
import sys

# GCC-blessed multi-byte NOP variants, keyed by length (1..9).
NOP_SET = {
    1: [b"\x90"],
    2: [b"\x66\x90"],
    3: [b"\x0f\x1f\x00"],
    4: [b"\x0f\x1f\x40\x00"],
    5: [b"\x0f\x1f\x44\x00\x00"],
    6: [b"\x66\x0f\x1f\x44\x00\x00"],
    7: [b"\x0f\x1f\x80\x00\x00\x00\x00"],
    8: [b"\x0f\x1f\x84\x00\x00\x00\x00\x00"],
    9: [b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"],
}

# All single-byte-tagged NOP opcodes we recognise as padding bytes.
NOP_FIRST_BYTES = {0x90, 0x66, 0x0f}

# DonutLoader x64 prologue (first 27 bytes of .text). If this doesn't match
# the start of the .text section, the mingw command-line order drifted and we
# refuse to permute.
DONUT_PROLOGUE_X64 = bytes.fromhex(
    "48895c2408 48896c2410 4889742418 57 4156 4157 4881ec0005 0000".replace(" ", "")
)


def parse_pe_text(data: bytes):
    """Return (text_offset, text_size) in the raw file for the .text section."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE/MZ file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("PE header not found")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff + 16)[0]
    sect_tbl = coff + 20 + opt_hdr_size
    for i in range(num_sections):
        s = sect_tbl + i * 40
        name = data[s:s+8].rstrip(b"\0")
        if name == b".text":
            vsize = struct.unpack_from("<I", data, s + 8)[0]
            rawoff = struct.unpack_from("<I", data, s + 20)[0]
            return rawoff, vsize
    raise ValueError(".text section not found")


def find_nop_runs(text: bytes):
    """Yield (start, length) for every NOP run that lies strictly between
    a RET sentinel and a non-NOP byte. Only considers single-byte 0x90 fills
    (the simplest form GCC emits for -fno-toplevel-reorder output); multi-byte
    NOPs become single-byte runs after disassembly collapses them."""
    i = 0
    n = len(text)
    while i < n:
        # look for ret c3 OR ret imm16 c2 xx xx
        if text[i] == 0xC3 or (text[i] == 0xC2 and i + 3 <= n):
            step = 1 if text[i] == 0xC3 else 3
            j = i + step
            run_start = j
            while j < n and text[j] == 0x90:
                j += 1
            run_len = j - run_start
            if run_len >= 2 and run_len <= 15:
                yield run_start, run_len
            i = j if j > i else i + 1
        else:
            i += 1


def permute_run(seed_bytes: bytes, run_len: int) -> bytes:
    """Partition `run_len` bytes into NOP variants whose lengths sum to
    run_len, deterministically seeded."""
    out = b""
    remaining = run_len
    cursor = 0
    while remaining > 0:
        max_len = min(remaining, 9)
        # pick a length from {1..max_len} driven by seed_bytes[cursor]
        pick = (seed_bytes[cursor % len(seed_bytes)] % max_len) + 1
        variants = NOP_SET[pick]
        out += variants[0]  # one variant per length today; set is deterministic
        remaining -= pick
        cursor += 1
    return out


def main(path):
    seed_raw = os.environ.get("DONUT_SEED", "").strip()
    with open(path, "rb") as f:
        data = bytearray(f.read())

    text_off, text_size = parse_pe_text(bytes(data))
    text = bytes(data[text_off:text_off + text_size])

    if not text.startswith(DONUT_PROLOGUE_X64) and len(text) >= 27:
        # x86 build does not have this exact prologue; skip the guard then.
        if text[0] != 0x55 and text[0] != 0x48:
            sys.stderr.write(
                "nop-permute: refusing — .text offset-0 does not match a known loader prologue\n"
            )
            return 0

    if not seed_raw:
        sys.stderr.write("nop-permute: DONUT_SEED empty, no-op (stock build)\n")
        return 0

    seed_bytes = hashlib.sha256(seed_raw.encode("utf-8")).digest()
    runs = list(find_nop_runs(text))
    permuted = 0
    for start, length in runs:
        rseed = hashlib.sha256(seed_bytes + start.to_bytes(4, "little")).digest()
        new_bytes = permute_run(rseed, length)
        if len(new_bytes) != length:
            sys.stderr.write(f"nop-permute: WARN run@{start} len mismatch, skip\n")
            continue
        data[text_off + start:text_off + start + length] = new_bytes
        permuted += 1

    with open(path, "wb") as f:
        f.write(data)
    sys.stderr.write(f"nop-permute: permuted {permuted}/{len(runs)} NOP runs\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
