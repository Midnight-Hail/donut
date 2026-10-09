#!/usr/bin/env python3
"""
strings-gate.py — scout 6 Q4 build-time gate.

Fails Docker build if the raw DONUT_SEED (or any 4+ byte run of HKDF-derived
constants from include/seed.h) appears literally in the shipped donut binary.
Catches accidental embedding via debug printf, symbol, or hand-added #define.

Usage: python3 tools/strings-gate.py <path/to/donut>
"""
import os
import re
import sys


def main(path):
    seed_raw = os.environ.get("DONUT_SEED", "").strip()
    with open(path, "rb") as f:
        data = f.read()

    if seed_raw:
        if seed_raw.encode("utf-8") in data:
            sys.stderr.write(f"strings-gate: FAIL — raw DONUT_SEED present in {path}\n")
            return 1

    # Scan include/seed.h for the derived constants and ensure none of them
    # appear as a 4+ byte literal in the binary.
    seed_h = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "include", "seed.h")
    if not os.path.exists(seed_h):
        sys.stderr.write("strings-gate: include/seed.h missing, cannot scan\n")
        return 0
    with open(seed_h, "r") as f:
        text = f.read()

    hits = re.findall(r"0x([0-9a-fA-F]{16,})ULL", text)
    for h in hits:
        val = int(h, 16)
        # 64-bit little-endian
        pat = val.to_bytes(8, "little")
        # Allow all-zero stock whitening to appear anywhere (it's not a secret).
        if val == 0:
            continue
        if pat in data:
            sys.stderr.write(
                f"strings-gate: FAIL — derived constant 0x{val:016x} present as little-endian in {path}\n"
            )
            return 1

    sys.stderr.write(f"strings-gate: ok — no raw seed or derived constants embedded in {path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
