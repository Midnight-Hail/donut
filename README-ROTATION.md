# donut rotation surface (Midnight-Hail fork)

Four hard facts future contributors must know before touching the
rotation infrastructure:

1. **Donut uses Chaskey + SPECK, NOT ChaCha20.** The literal string
   `expand 32-byte k` is NOT present in this codebase. Any PR message
   that claims to rotate ChaCha constants is in the wrong tree.
2. **Donut has ZERO mutexes and ZERO named pipes.** Grep is clean.
3. **The 15 GUIDs in `donut.c` are mandatory Windows COM/CLR interface
   IDs** (CB2F6723 CorRuntimeHost, D332DB9E ICLRMetaHost, 05F696DC
   AppDomain, BB1A2AE1 IActiveScript, …). Randomising them breaks
   .NET assembly loading and VBS/JS execution.
4. **The hardcoded Microsoft API name strings** (`AmsiInitialize`,
   `EtwEventWrite`, `VirtualAlloc`, `.data`, `kernelbase`, …) are
   literal `GetProcAddress` inputs. They CANNOT be randomised without
   replacing `GetProcAddress` entirely — a different workstream.

## What this rotation touches

Single input knob: environment variable `DONUT_SEED`. Driven through
HKDF-SHA256 by `tools/seed-gen.py` into `include/seed.h`, which both the
generator and the baked loader `#include`.

| Axis | Where | Stock | Rotated |
|------|-------|-------|---------|
| Chaskey rotation order | `encrypt.c:chaskey()` slot 0..5 | `{27,24,16,19,25,16}` | permutation of same set |
| Chaskey state-whitening | `encrypt.c:chaskey()` | zero XOR | 128-bit XOR mask |
| SPECK alpha rotation | `hash.c:speck()` | 8 | ∈ {7,8,9} |
| SPECK beta rotation (inv) | `hash.c:speck()` | 29 | ∈ {27,28,29,30} |
| Inter-function NOP padding | baked loader `.text` | GCC default | seeded permutation |

## What this rotation does NOT do

- **Behavioural signal #1 — API call sequence (NtAlloc→NtProtect→execute)**
  survives any seed. Rotation defeats static signatures only. Behavioural
  defeats (APC dispatch, module stomping, SEC_IMAGE mapping) are a separate
  workstream.
- **Export symbol rename** (`DonutCreate`/`DonutDelete`/`DonutLoader`) is
  OUT OF SCOPE here because it couples `libdonut.so` consumers
  (`donutmodule.c`, the Midnight-Hail Python preprocessor at
  `common/preprocessors/donut.py`, …) to the rotated names. The CLI
  binary consumed by Midnight-Hail's StaticBypass is stripped and has
  no public symbol surface.

## CI gates

Every non-empty-seed Docker build must pass:

1. `make kat && ./kat` — round-trip + non-identity + maru stability.
2. `tools/strings-gate.py donut` — no raw seed or derived constant
   literals embedded in the shipped binary.
3. `tools/seed-gen.py` collision check — SPECK rotation must not collide
   two API names in the internal api_imports[] table.
4. `tests/sig-regression.sh` — 5-seed build with pairwise sha256
   divergence on both `donut` AND `loader_exe_x64.h`.

## Decisive on-range verification

Stage a payload with empty DONUT_SEED (expect current stock YARA hits on
Elastic/Suricata keyed on Chaskey/SPECK byte patterns), then stage the
same payload with a non-empty seed. Win = static YARA goes silent AND
payload still detonates (Beacon/Meterpreter callbacks). Silent EDR
behavioural chain is NOT claimed by this rotation.
