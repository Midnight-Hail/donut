/*
 * Known-Answer-Test for donut rotation PRs.
 *
 * Links against the SAME encrypt.c + hash.c the shipped generator links.
 * Scout 6 Q1: a parallel reimplementation would happily agree with itself
 * while production is broken. This file CANNOT drift from production
 * because it compiles the production primitives directly.
 *
 * Checks:
 *   (A) donut_encrypt round-trips 1024 bytes under fixed key/CTR
 *   (B) encrypt(pt) != pt — rules out identity-map Chaskey degeneracy
 *   (C) maru("LoadLibraryA", 0x8E63EC0D29F27D07) is non-zero AND stable
 *       across two calls (deterministic hash under current SPECK rotations)
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "encrypt.h"
#include "hash.h"

void donut_encrypt(void *mk, void *ctr, void *data, uint32_t len);
uint64_t maru(const void *input, uint64_t iv);

static uint8_t KEY[16] = {
    0x56,0x09,0xe9,0x68,0x5f,0x58,0xe3,0x29,
    0x40,0xec,0xec,0x98,0xc5,0x22,0x98,0x2f
};

static uint8_t CTR0[16] = {
    0xd0,0x01,0x36,0x9b,0xef,0x6a,0xa1,0x05,
    0x1d,0x2d,0x21,0x98,0x19,0x8d,0x88,0x93
};

#define PLAIN_LEN 1024

int main(void) {
    uint8_t plain[PLAIN_LEN];
    uint8_t work[PLAIN_LEN];
    uint8_t ctr[16];
    int i, failures = 0;

    for (i = 0; i < PLAIN_LEN; i++) plain[i] = (uint8_t)(i * 7 + 11);

    /* (A) round-trip under CTR mode (encrypt == decrypt). */
    memcpy(work, plain, PLAIN_LEN);
    memcpy(ctr, CTR0, 16);
    donut_encrypt(KEY, ctr, work, PLAIN_LEN);

    /* (B) first-encryption changes bytes — catches identity-map Chaskey. */
    if (memcmp(work, plain, PLAIN_LEN) == 0) {
        fprintf(stderr, "KAT FAIL: encrypt(pt) == pt (identity-map Chaskey)\n");
        failures++;
    }

    memcpy(ctr, CTR0, 16);
    donut_encrypt(KEY, ctr, work, PLAIN_LEN);
    if (memcmp(work, plain, PLAIN_LEN) != 0) {
        fprintf(stderr, "KAT FAIL: round-trip (decrypt(encrypt(pt)) != pt)\n");
        failures++;
    }

    /* (C) maru stability + non-zero. */
    uint64_t h1 = maru("LoadLibraryA", 0x8E63EC0D29F27D07ULL);
    uint64_t h2 = maru("LoadLibraryA", 0x8E63EC0D29F27D07ULL);
    if (h1 == 0) { fprintf(stderr, "KAT FAIL: maru returned 0\n"); failures++; }
    if (h1 != h2) { fprintf(stderr, "KAT FAIL: maru non-deterministic\n"); failures++; }

    if (failures) {
        fprintf(stderr, "KAT: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stdout, "KAT ok: round-trip + Chaskey-non-identity + maru stable (h=0x%016llx)\n",
            (unsigned long long)h1);
    return 0;
}
