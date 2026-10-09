/**
  BSD 3-Clause License
  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.
  Midnight-Hail rotation patches (c) 2026 Midnight-Hail. All rotation knobs
  live in include/seed.h; stock seed.h reproduces upstream behaviour.
*/

#include "encrypt.h"
#include "seed.h"

#include <stdio.h>
#include <string.h>

static void chaskey(void *mk, void *p) {
    uint32_t i,*w=p,*k=mk;
    uint64_t *w64 = (uint64_t*)p;

    // add 128-bit master key
    for(i=0;i<4;i++) w[i]^=k[i];

    // state-whitening XOR (symmetric: applied again post-permutation).
    // Stock seed.h sets both masks to 0 so this is a no-op in baseline builds.
    w64[0] ^= ROT_CHASKEY_WHITEN_LO;
    w64[1] ^= ROT_CHASKEY_WHITEN_HI;

    // apply 16 rounds of permutation. Rotation amounts come from seed.h —
    // stock values are {27,24,16,19,25,16}; a non-stock seed permutes
    // the order these are applied at the six fixed slots.
    for(i=0;i<16;i++) {
      w[0] += w[1],
      w[1]  = ROTR32(w[1], ROT_CHASKEY_R0) ^ w[0],
      w[2] += w[3],
      w[3]  = ROTR32(w[3], ROT_CHASKEY_R1) ^ w[2],
      w[2] += w[1],
      w[0]  = ROTR32(w[0], ROT_CHASKEY_R2) + w[3],
      w[3]  = ROTR32(w[3], ROT_CHASKEY_R3) ^ w[0],
      w[1]  = ROTR32(w[1], ROT_CHASKEY_R4) ^ w[2],
      w[2]  = ROTR32(w[2], ROT_CHASKEY_R5);
    }

    // symmetric whitening cancellation.
    w64[0] ^= ROT_CHASKEY_WHITEN_LO;
    w64[1] ^= ROT_CHASKEY_WHITEN_HI;

    // add 128-bit master key
    for(i=0;i<4;i++) w[i]^=k[i];
}

// encrypt/decrypt data in counter mode
void donut_encrypt(void *mk, void *ctr, void *data, uint32_t len) {
    uint8_t  x[CIPHER_BLK_LEN],
             *p=(uint8_t*)data,
             *c=(uint8_t*)ctr;
    uint32_t      i, r;

    while(len) {
      for(i=0;i<CIPHER_BLK_LEN;i++)
        x[i] = c[i];

      ENCRYPT(mk, &x);

      r = len > CIPHER_BLK_LEN ? CIPHER_BLK_LEN : len;

      for(i=0;i<r;i++)
        p[i] ^= x[i];

      len -= r; p += r;

      for(i=CIPHER_BLK_LEN;(int)i>0;i--)
        if(++c[i-1]) break;
    }
}

/* TEST harness unchanged — note that the published chaskey test vector
 * (plain_tv -> cipher_tv) only matches under STOCK seed.h. Non-stock
 * builds will fail that specific vector; the KAT in tools/kat.c tests
 * the ROUND-TRIP invariant which must hold under any rotation. */
