/**
  BSD 3-Clause License
  Copyright (c) 2017 Odzhan. All rights reserved.
  Midnight-Hail rotation patches (c) 2026 Midnight-Hail.
*/

#include "hash.h"
#include "seed.h"

// SPECK-64/128 with rotation amounts from seed.h.
// Stock seed.h: ALPHA=8, BETA_INV=29 (== 32-3) — matches upstream.
static uint64_t speck(void *mk, uint64_t p) {
    uint32_t k[4], i, t;
    union {
      uint32_t w[2];
      uint64_t q;
    } x;

    x.q = p;

    for(i=0;i<4;i++) k[i]=((uint32_t*)mk)[i];

    for(i=0;i<27;i++) {
      x.w[0] = (ROTR32(x.w[0], ROT_SPECK_ALPHA) + x.w[1]) ^ k[0];
      x.w[1] =  ROTR32(x.w[1], ROT_SPECK_BETA_INV) ^ x.w[0];

      t = k[3];
      k[3] = (ROTR32(k[1], ROT_SPECK_ALPHA) + k[0]) ^ i;
      k[0] =  ROTR32(k[0], ROT_SPECK_BETA_INV) ^ k[3];

      k[1] = k[2];
      k[2] = t;
    }
    return x.q;
}

uint64_t maru(const void *input, uint64_t iv) {
    uint64_t h;
    uint32_t len, idx, end;
    const char *api = (const char*)input;

    union {
      uint8_t  b[MARU_BLK_LEN];
      uint32_t w[MARU_BLK_LEN/4];
    } m;

    h = iv;

    for(idx=0, len=0, end=0;!end;) {
      if(api[len] == 0 || len == MARU_MAX_STR) {
        Memset(&m.b[idx], 0, MARU_BLK_LEN - idx);
        m.b[idx] = 0x80;
        if(idx >= MARU_BLK_LEN - 4) {
          h ^= MARU_CRYPT(&m, h);
          Memset(&m, 0, MARU_BLK_LEN);
        }
        m.w[(MARU_BLK_LEN/4)-1] = (len * 8);
        idx = MARU_BLK_LEN;
        end++;
      } else {
        m.b[idx] = (uint8_t)api[len];
        idx++; len++;
      }
      if(idx == MARU_BLK_LEN) {
        h ^= MARU_CRYPT(&m, h);
        idx = 0;
      }
    }
    return h;
}

/* TEST harness unchanged — stock seed.h makes the published maru_tv table
 * valid; non-stock builds derive different hashes (that's the point) and
 * the collision-check in tools/seed-gen.py guards against pathological
 * rotations that collide the api_imports[] table. */
