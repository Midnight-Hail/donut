/*
 * donut rotation seed header — STOCK baseline (upstream-identical values).
 *
 * This committed stock copy makes a bare `make donut` without DONUT_SEED
 * build verbatim upstream behaviour. tools/seed-gen.py OVERWRITES this file
 * in-place during CI builds when DONUT_SEED is non-empty; the overwrite is
 * build-local and does not leak into the final image because the only
 * artifact COPY'd forward is /src/donut (and /src/loader_exe_x64.h as baked
 * into the generator at compile time). See README-ROTATION.md.
 *
 * These four axes rotate per DONUT_SEED:
 *   ROT_CHASKEY_R0..R5         — the 6 rotation amounts in encrypt.c:chaskey()
 *                                permuted from stock set {27,24,16,19,25,16}
 *   ROT_CHASKEY_WHITEN_LO/HI   — two 64-bit XOR masks applied symmetrically
 *                                to the Chaskey state before AND after the
 *                                permutation (cancels bytewise, moves ciphertext)
 *   ROT_SPECK_ALPHA            — SPECK round-function first rotation (stock 8)
 *   ROT_SPECK_BETA_INV         — SPECK round-function second rotation inverse
 *                                (stock 29, == 32-3)
 */
#ifndef DONUT_SEED_H
#define DONUT_SEED_H

/* Chaskey rotation-order permutation — stock values, in stock order. */
#define ROT_CHASKEY_R0 27U
#define ROT_CHASKEY_R1 24U
#define ROT_CHASKEY_R2 16U
#define ROT_CHASKEY_R3 19U
#define ROT_CHASKEY_R4 25U
#define ROT_CHASKEY_R5 16U

/* Chaskey state-whitening XOR masks — zero in stock (no-op). */
#define ROT_CHASKEY_WHITEN_LO 0x0000000000000000ULL
#define ROT_CHASKEY_WHITEN_HI 0x0000000000000000ULL

/* SPECK-64/128 round rotations — stock values. BETA_INV == 32 - BETA. */
#define ROT_SPECK_ALPHA    8U
#define ROT_SPECK_BETA_INV 29U

#endif /* DONUT_SEED_H */
