#!/usr/bin/env python3
"""
seed-gen.py — derive donut rotation constants from DONUT_SEED via HKDF-SHA256.

Reads DONUT_SEED from the environment. If empty/missing, prints a one-line
notice to stderr and emits stock constants (byte-identical to the committed
include/seed.h). If non-empty, derives:

  * ROT_CHASKEY_ORDER[6]     — permutation of {0..5} indexing stock Chaskey
                               rotations {27,24,16,19,25,16}; applied to
                               produce ROT_CHASKEY_R0..R5
  * ROT_CHASKEY_WHITEN_LO/HI — two independent 64-bit XOR masks
  * ROT_SPECK_ALPHA/BETA     — drawn from the SPECK-standard neighbourhood
                               {7,8,9} x {2,3,4,5} so the dual-rotation
                               invariant stays intact

After deriving candidate SPECK rotations, runs an INTERNAL collision check:
maru(name, baseline_iv) over the 60+ hardcoded Microsoft API names in
donut.c must produce 60+ distinct 64-bit hashes. If any pair collides,
re-derives with a bumped counter until the collision set is empty or we
hit the retry cap (fail-stop).

Stdout is unused; the file is written to include/seed.h relative to the
script's parent directory. Stderr prints ONLY one line and NEVER contains
the raw DONUT_SEED (scout 6 Q4) — only a sha256 fingerprint of it.
"""
import hashlib
import hmac
import os
import sys

# Hardcoded Microsoft API names from donut.c api_imports[] — the set the
# SPECK rotation must not collide on. Captured once from donut.c:46-121.
# A collision here means the baked loader resolves (e.g.) VirtualAlloc to the
# wrong function silently.
API_NAMES = [
    "LoadLibraryA", "GetProcAddress", "GetModuleHandleA", "VirtualAlloc",
    "VirtualFree", "VirtualQuery", "VirtualProtect", "Sleep", "MultiByteToWideChar",
    "GetUserDefaultLCID", "WaitForSingleObject", "CreateThread", "GetThreadContext",
    "GetCurrentThread", "GetCommandLineA", "GetCommandLineW", "HeapAlloc",
    "HeapReAlloc", "HeapFree", "GetProcessHeap", "LocalAlloc", "LocalReAlloc",
    "LocalFree", "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
    "SetUnhandledExceptionFilter", "ExitProcess", "ExitThread", "RtlExitUserThread",
    "RtlAddFunctionTable", "RtlCaptureContext", "RtlLookupFunctionEntry",
    "RtlVirtualUnwind", "NtContinue", "NtTerminateProcess", "RtlZeroMemory",
    "CorBindToRuntime", "CLRCreateInstance", "SafeArrayCreate", "SafeArrayCreateVector",
    "SafeArrayPutElement", "SafeArrayDestroy", "SafeArrayGetLBound",
    "SafeArrayGetUBound", "SysAllocString", "SysFreeString", "LoadLibraryExA",
    "CreateActCtxA", "ActivateActCtx", "GetFileAttributesA", "GetTempPathA",
    "GetModuleHandleExA", "CoInitializeEx", "CoCreateInstance", "CoUninitialize",
    "OleRun", "AmsiInitialize", "AmsiScanBuffer", "AmsiScanString", "WldpQueryDynamicCodeTrust",
    "WldpIsClassInApprovedList", "EtwEventWrite", "EtwEventUnregister",
]

# Stock Chaskey rotation set, in stock order.
STOCK_CHASKEY = (27, 24, 16, 19, 25, 16)

# Stock baseline IV used by the generator — stable test IV, not a secret.
BASELINE_IV = 0x8E63EC0D29F27D07


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def permute_order(seed: bytes) -> list:
    """Return a Fisher-Yates permutation of [0..5] driven by `seed` bytes."""
    arr = list(range(6))
    for i in range(5, 0, -1):
        j = seed[i] % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return arr


def rotr32(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def speck_hash(key_bytes: bytes, p: int, alpha: int, beta_inv: int) -> int:
    """Python mirror of hash.c speck() under given rotations. Returns 64-bit."""
    k = [int.from_bytes(key_bytes[i:i+4], "little") for i in range(0, 16, 4)]
    x0 = p & 0xFFFFFFFF
    x1 = (p >> 32) & 0xFFFFFFFF
    for i in range(27):
        x0 = ((rotr32(x0, alpha) + x1) & 0xFFFFFFFF) ^ k[0]
        x1 = rotr32(x1, beta_inv) ^ x0
        t = k[3]
        k[3] = ((rotr32(k[1], alpha) + k[0]) & 0xFFFFFFFF) ^ i
        k[0] = rotr32(k[0], beta_inv) ^ k[3]
        k[1] = k[2]
        k[2] = t
    return (x1 << 32) | x0


def maru_hash(name: str, iv: int, speck_key: bytes, alpha: int, beta_inv: int) -> int:
    """Python mirror of hash.c maru() under given SPECK rotations."""
    BLK = 16
    MAX_STR = 64
    h = iv
    m = bytearray(BLK)
    idx = 0
    length = 0
    data = name.encode("ascii")
    end = False
    while not end:
        if length >= len(data) or length == MAX_STR:
            for i in range(idx, BLK):
                m[i] = 0
            m[idx] = 0x80
            if idx >= BLK - 4:
                h ^= speck_hash(bytes(m), h, alpha, beta_inv)
                m = bytearray(BLK)
            m[BLK-4:BLK] = (length * 8).to_bytes(4, "little")
            idx = BLK
            end = True
        else:
            m[idx] = data[length]
            idx += 1
            length += 1
        if idx == BLK:
            h ^= speck_hash(bytes(m), h, alpha, beta_inv)
            idx = 0
            m = bytearray(BLK)
    return h & 0xFFFFFFFFFFFFFFFF


def derive(seed_raw: str, counter: int) -> dict:
    ikm = seed_raw.encode("utf-8")
    salt = b"donut-rotation-v1"
    tag = f"attempt-{counter}".encode("ascii")

    order_bytes = hkdf(ikm, salt, b"chaskey-order|" + tag, 6)
    order = permute_order(order_bytes)

    whiten = hkdf(ikm, salt, b"chaskey-whiten|" + tag, 16)
    whiten_lo = int.from_bytes(whiten[:8], "little")
    whiten_hi = int.from_bytes(whiten[8:], "little")

    speck_bytes = hkdf(ikm, salt, b"speck-rot|" + tag, 2)
    alpha = 7 + (speck_bytes[0] % 3)             # {7,8,9}
    beta = 2 + (speck_bytes[1] % 3)              # {2,3,4} — brief-stated SPECK-standard neighbourhood
    beta_inv = 32 - beta

    return {
        "order": order,
        "whiten_lo": whiten_lo,
        "whiten_hi": whiten_hi,
        "alpha": alpha,
        "beta_inv": beta_inv,
    }


def collision_check(d: dict) -> bool:
    key = bytes.fromhex("5609e9685f58e32940ecec98c522982f")  # key_tv from encrypt.c TEST
    seen = {}
    for name in API_NAMES:
        h = maru_hash(name, BASELINE_IV, key, d["alpha"], d["beta_inv"])
        if h in seen:
            return False
        seen[h] = name
    return True


def emit(out_path: str, d: dict):
    chaskey_vals = [STOCK_CHASKEY[d["order"][i]] for i in range(6)]
    with open(out_path, "w") as f:
        f.write("/* AUTO-GENERATED by tools/seed-gen.py from DONUT_SEED. */\n")
        f.write("#ifndef DONUT_SEED_H\n#define DONUT_SEED_H\n\n")
        for i, v in enumerate(chaskey_vals):
            f.write(f"#define ROT_CHASKEY_R{i} {v}U\n")
        f.write(f"\n#define ROT_CHASKEY_WHITEN_LO 0x{d['whiten_lo']:016x}ULL\n")
        f.write(f"#define ROT_CHASKEY_WHITEN_HI 0x{d['whiten_hi']:016x}ULL\n\n")
        f.write(f"#define ROT_SPECK_ALPHA    {d['alpha']}U\n")
        f.write(f"#define ROT_SPECK_BETA_INV {d['beta_inv']}U\n\n")
        f.write("#endif /* DONUT_SEED_H */\n")


def main():
    seed_raw = os.environ.get("DONUT_SEED", "").strip()
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "include", "seed.h")

    if not seed_raw:
        sys.stderr.write("seed-gen: DONUT_SEED empty, keeping committed stock include/seed.h\n")
        return 0

    fp = hashlib.sha256(seed_raw.encode("utf-8")).hexdigest()[:12]
    sys.stderr.write(f"seed-gen: deriving rotation constants (seed-fp={fp})\n")

    for counter in range(32):
        d = derive(seed_raw, counter)
        if collision_check(d):
            emit(out_path, d)
            sys.stderr.write(f"seed-gen: emitted {out_path} (attempt {counter})\n")
            return 0
        sys.stderr.write(f"seed-gen: SPECK rotation collision on API table, re-deriving (attempt {counter})\n")

    sys.stderr.write("seed-gen: FAILED to find collision-free rotation in 32 attempts\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
