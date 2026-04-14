/*
   BLAKE2 source code package - triple-path implementation
   Path 1: SSE2/SSE4.1/AVX optimized (x86/x86_64)
   Path 2: ARM NEON optimized (aarch64/arm with NEON)
   Path 3: Portable scalar fallback (any platform)

   Based on reference implementations by Samuel Neves <sneves@dei.uc.pt>
   NEON implementation from BLAKE2 official repository (github.com/BLAKE2/BLAKE2)

   CC0 1.0 Universal / OpenSSL License / Apache 2.0 (at your option)
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2.h"
#include "blake2-impl.h"
#include "blake2-config.h"

/* ========================================================================
   Path selection: SSE2 > ARM NEON > Scalar
   ======================================================================== */
#if defined(HAVE_SSE2)
  #define BLAKE2B_PATH_SSE2
#elif defined(__aarch64__) || (defined(__ARM_NEON) && defined(__ARM_64BIT_STATE))
  #define BLAKE2B_PATH_NEON
#endif

/* ========================================================================
   SSE2 includes
   ======================================================================== */
#if defined(BLAKE2B_PATH_SSE2)

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include <emmintrin.h>
#if defined(_MSC_VER) && !defined(_M_X64) && !defined(__clang__)
static inline __m128i _mm_set_epi64x(const uint64_t u1, const uint64_t u0)
{
  return _mm_set_epi32(u1 >> 32, u1, u0 >> 32, u0);
}
#endif

#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP) && !defined(_MSC_VER)
#include <x86intrin.h>
#endif

#include "blake2b-round.h"

#endif /* BLAKE2B_PATH_SSE2 */

/* ========================================================================
   ARM NEON includes
   ======================================================================== */
#if defined(BLAKE2B_PATH_NEON)
#include <arm_neon.h>
#endif

/* ========================================================================
   Constants (shared by all paths)
   ======================================================================== */

static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static inline int blake2b_set_lastnode( blake2b_state *S )
{
  S->f[1] = ~0ULL;
  return 0;
}

static inline int blake2b_clear_lastnode( blake2b_state *S )
{
  S->f[1] = 0ULL;
  return 0;
}

static inline int blake2b_set_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_set_lastnode( S );
  S->f[0] = ~0ULL;
  return 0;
}

static inline int blake2b_clear_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_clear_lastnode( S );
  S->f[0] = 0ULL;
  return 0;
}

static inline int blake2b_increment_counter( blake2b_state *S, const uint64_t inc )
{
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
  __uint128_t t = ( ( __uint128_t )S->t[1] << 64 ) | S->t[0];
  t += inc;
  S->t[0] = ( uint64_t )( t >>  0 );
  S->t[1] = ( uint64_t )( t >> 64 );
#else
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
#endif
  return 0;
}

/* ========================================================================
   blake2b_compress - Path 1: SSE2/SSE4.1/AVX (x86)
   ======================================================================== */
#if defined(BLAKE2B_PATH_SSE2)

static inline int blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
  const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
  const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );
#endif
#if defined(HAVE_SSE41)
  const __m128i m0 = LOADU( block + 00 );
  const __m128i m1 = LOADU( block + 16 );
  const __m128i m2 = LOADU( block + 32 );
  const __m128i m3 = LOADU( block + 48 );
  const __m128i m4 = LOADU( block + 64 );
  const __m128i m5 = LOADU( block + 80 );
  const __m128i m6 = LOADU( block + 96 );
  const __m128i m7 = LOADU( block + 112 );
#else
  const uint64_t  m0 = ( ( uint64_t * )block )[ 0];
  const uint64_t  m1 = ( ( uint64_t * )block )[ 1];
  const uint64_t  m2 = ( ( uint64_t * )block )[ 2];
  const uint64_t  m3 = ( ( uint64_t * )block )[ 3];
  const uint64_t  m4 = ( ( uint64_t * )block )[ 4];
  const uint64_t  m5 = ( ( uint64_t * )block )[ 5];
  const uint64_t  m6 = ( ( uint64_t * )block )[ 6];
  const uint64_t  m7 = ( ( uint64_t * )block )[ 7];
  const uint64_t  m8 = ( ( uint64_t * )block )[ 8];
  const uint64_t  m9 = ( ( uint64_t * )block )[ 9];
  const uint64_t m10 = ( ( uint64_t * )block )[10];
  const uint64_t m11 = ( ( uint64_t * )block )[11];
  const uint64_t m12 = ( ( uint64_t * )block )[12];
  const uint64_t m13 = ( ( uint64_t * )block )[13];
  const uint64_t m14 = ( ( uint64_t * )block )[14];
  const uint64_t m15 = ( ( uint64_t * )block )[15];
#endif
  row1l = LOADU( &S->h[0] );
  row1h = LOADU( &S->h[2] );
  row2l = LOADU( &S->h[4] );
  row2h = LOADU( &S->h[6] );
  row3l = LOADU( &blake2b_IV[0] );
  row3h = LOADU( &blake2b_IV[2] );
  row4l = _mm_xor_si128( LOADU( &blake2b_IV[4] ), LOADU( &S->t[0] ) );
  row4h = _mm_xor_si128( LOADU( &blake2b_IV[6] ), LOADU( &S->f[0] ) );
  ROUND( 0 );  ROUND( 1 );  ROUND( 2 );  ROUND( 3 );
  ROUND( 4 );  ROUND( 5 );  ROUND( 6 );  ROUND( 7 );
  ROUND( 8 );  ROUND( 9 );  ROUND( 10 ); ROUND( 11 );
  row1l = _mm_xor_si128( row3l, row1l );
  row1h = _mm_xor_si128( row3h, row1h );
  STOREU( &S->h[0], _mm_xor_si128( LOADU( &S->h[0] ), row1l ) );
  STOREU( &S->h[2], _mm_xor_si128( LOADU( &S->h[2] ), row1h ) );
  row2l = _mm_xor_si128( row4l, row2l );
  row2h = _mm_xor_si128( row4h, row2h );
  STOREU( &S->h[4], _mm_xor_si128( LOADU( &S->h[4] ), row2l ) );
  STOREU( &S->h[6], _mm_xor_si128( LOADU( &S->h[6] ), row2h ) );
  return 0;
}

/* ========================================================================
   blake2b_compress - Path 2: ARM NEON (aarch64)
   From BLAKE2 official repository: github.com/BLAKE2/BLAKE2/neon/
   ======================================================================== */
#elif defined(BLAKE2B_PATH_NEON)

/* NEON rotation primitives */
#define vrorq_n_u64_32(x) vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64((x))))

#define vrorq_n_u64_24(x) vcombine_u64( \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 3)), \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 3)))

#define vrorq_n_u64_16(x) vcombine_u64( \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 2)), \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 2)))

#define vrorq_n_u64_63(x) veorq_u64(vaddq_u64(x, x), vshrq_n_u64(x, 63))

/* NEON G mixing functions */
#define NEON_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  do { \
    row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
    row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
    row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
    row4l = vrorq_n_u64_32(row4l); row4h = vrorq_n_u64_32(row4h); \
    row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
    row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
    row2l = vrorq_n_u64_24(row2l); row2h = vrorq_n_u64_24(row2h); \
  } while(0)

#define NEON_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  do { \
    row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
    row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
    row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
    row4l = vrorq_n_u64_16(row4l); row4h = vrorq_n_u64_16(row4h); \
    row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
    row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
    row2l = vrorq_n_u64_63(row2l); row2h = vrorq_n_u64_63(row2h); \
  } while(0)

#define NEON_DIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  do { \
    uint64x2_t t0 = vextq_u64(row2l, row2h, 1); \
    uint64x2_t t1 = vextq_u64(row2h, row2l, 1); \
    row2l = t0; row2h = t1; t0 = row3l; row3l = row3h; row3h = t0; \
    t0 = vextq_u64(row4h, row4l, 1); t1 = vextq_u64(row4l, row4h, 1); \
    row4l = t0; row4h = t1; \
  } while(0)

#define NEON_UNDIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  do { \
    uint64x2_t t0 = vextq_u64(row2h, row2l, 1); \
    uint64x2_t t1 = vextq_u64(row2l, row2h, 1); \
    row2l = t0; row2h = t1; t0 = row3l; row3l = row3h; row3h = t0; \
    t0 = vextq_u64(row4l, row4h, 1); t1 = vextq_u64(row4h, row4l, 1); \
    row4l = t0; row4h = t1; \
  } while(0)

/* NEON message loading macros - optimized permutations for each round */
#define NEON_LOAD_MSG_0_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)); } while(0)
#define NEON_LOAD_MSG_0_2(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)); } while(0)
#define NEON_LOAD_MSG_0_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)
#define NEON_LOAD_MSG_0_4(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)); } while(0)

#define NEON_LOAD_MSG_1_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)); } while(0)
#define NEON_LOAD_MSG_1_2(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vextq_u64(m7, m3, 1); } while(0)
#define NEON_LOAD_MSG_1_3(b0, b1) do { b0 = vextq_u64(m0, m0, 1); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)); } while(0)
#define NEON_LOAD_MSG_1_4(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); } while(0)

#define NEON_LOAD_MSG_2_1(b0, b1) do { b0 = vextq_u64(m5, m6, 1); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); } while(0)
#define NEON_LOAD_MSG_2_2(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m0)); b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m6)); } while(0)
#define NEON_LOAD_MSG_2_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m5), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m4)); } while(0)
#define NEON_LOAD_MSG_2_4(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m3)); b1 = vextq_u64(m0, m2, 1); } while(0)

#define NEON_LOAD_MSG_3_1(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m5)); } while(0)
#define NEON_LOAD_MSG_3_2(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m0)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)
#define NEON_LOAD_MSG_3_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)); } while(0)
#define NEON_LOAD_MSG_3_4(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)); } while(0)

#define NEON_LOAD_MSG_4_1(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m5)); } while(0)
#define NEON_LOAD_MSG_4_2(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m0), vget_high_u64(m3)); b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)); } while(0)
#define NEON_LOAD_MSG_4_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m5)); b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m1)); } while(0)
#define NEON_LOAD_MSG_4_4(b0, b1) do { b0 = vextq_u64(m0, m6, 1); b1 = vcombine_u64(vget_low_u64(m4), vget_high_u64(m6)); } while(0)

#define NEON_LOAD_MSG_5_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m3)); b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)); } while(0)
#define NEON_LOAD_MSG_5_2(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m5)); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m1)); } while(0)
#define NEON_LOAD_MSG_5_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m3)); b1 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m0)); } while(0)
#define NEON_LOAD_MSG_5_4(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m4)); } while(0)

#define NEON_LOAD_MSG_6_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m0)); b1 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); } while(0)
#define NEON_LOAD_MSG_6_2(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); b1 = vextq_u64(m6, m5, 1); } while(0)
#define NEON_LOAD_MSG_6_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m3)); b1 = vextq_u64(m4, m4, 1); } while(0)
#define NEON_LOAD_MSG_6_4(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m5)); } while(0)

#define NEON_LOAD_MSG_7_1(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m3)); b1 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m1)); } while(0)
#define NEON_LOAD_MSG_7_2(b0, b1) do { b0 = vextq_u64(m5, m7, 1); b1 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m4)); } while(0)
#define NEON_LOAD_MSG_7_3(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); b1 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m1)); } while(0)
#define NEON_LOAD_MSG_7_4(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m2)); b1 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); } while(0)

#define NEON_LOAD_MSG_8_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m7)); b1 = vextq_u64(m5, m0, 1); } while(0)
#define NEON_LOAD_MSG_8_2(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); b1 = vextq_u64(m1, m4, 1); } while(0)
#define NEON_LOAD_MSG_8_3(b0, b1) do { b0 = m6; b1 = vextq_u64(m0, m5, 1); } while(0)
#define NEON_LOAD_MSG_8_4(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m3)); b1 = m2; } while(0)

#define NEON_LOAD_MSG_9_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m0)); } while(0)
#define NEON_LOAD_MSG_9_2(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m2)); b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m2)); } while(0)
#define NEON_LOAD_MSG_9_3(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); b1 = vcombine_u64(vget_high_u64(m1), vget_high_u64(m6)); } while(0)
#define NEON_LOAD_MSG_9_4(b0, b1) do { b0 = vextq_u64(m5, m7, 1); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m0)); } while(0)

#define NEON_LOAD_MSG_10_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)); } while(0)
#define NEON_LOAD_MSG_10_2(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)); } while(0)
#define NEON_LOAD_MSG_10_3(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)
#define NEON_LOAD_MSG_10_4(b0, b1) do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)); } while(0)

#define NEON_LOAD_MSG_11_1(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)); } while(0)
#define NEON_LOAD_MSG_11_2(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vextq_u64(m7, m3, 1); } while(0)
#define NEON_LOAD_MSG_11_3(b0, b1) do { b0 = vextq_u64(m0, m0, 1); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)); } while(0)
#define NEON_LOAD_MSG_11_4(b0, b1) do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); } while(0)

#define NEON_ROUND(r) \
  do { \
    uint64x2_t b0, b1; \
    NEON_LOAD_MSG_##r##_1(b0, b1); \
    NEON_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    NEON_LOAD_MSG_##r##_2(b0, b1); \
    NEON_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    NEON_DIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
    NEON_LOAD_MSG_##r##_3(b0, b1); \
    NEON_G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    NEON_LOAD_MSG_##r##_4(b0, b1); \
    NEON_G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    NEON_UNDIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
  } while(0)

static int blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
  const uint64x2_t m0 = vreinterpretq_u64_u8(vld1q_u8(&block[  0]));
  const uint64x2_t m1 = vreinterpretq_u64_u8(vld1q_u8(&block[ 16]));
  const uint64x2_t m2 = vreinterpretq_u64_u8(vld1q_u8(&block[ 32]));
  const uint64x2_t m3 = vreinterpretq_u64_u8(vld1q_u8(&block[ 48]));
  const uint64x2_t m4 = vreinterpretq_u64_u8(vld1q_u8(&block[ 64]));
  const uint64x2_t m5 = vreinterpretq_u64_u8(vld1q_u8(&block[ 80]));
  const uint64x2_t m6 = vreinterpretq_u64_u8(vld1q_u8(&block[ 96]));
  const uint64x2_t m7 = vreinterpretq_u64_u8(vld1q_u8(&block[112]));

  uint64x2_t row1l, row1h, row2l, row2h;
  uint64x2_t row3l, row3h, row4l, row4h;

  const uint64x2_t h0 = row1l = vld1q_u64(&S->h[0]);
  const uint64x2_t h1 = row1h = vld1q_u64(&S->h[2]);
  const uint64x2_t h2 = row2l = vld1q_u64(&S->h[4]);
  const uint64x2_t h3 = row2h = vld1q_u64(&S->h[6]);

  row3l = vld1q_u64(&blake2b_IV[0]);
  row3h = vld1q_u64(&blake2b_IV[2]);
  row4l = veorq_u64(vld1q_u64(&blake2b_IV[4]), vld1q_u64(&S->t[0]));
  row4h = veorq_u64(vld1q_u64(&blake2b_IV[6]), vld1q_u64(&S->f[0]));

  NEON_ROUND( 0 );  NEON_ROUND( 1 );  NEON_ROUND( 2 );  NEON_ROUND( 3 );
  NEON_ROUND( 4 );  NEON_ROUND( 5 );  NEON_ROUND( 6 );  NEON_ROUND( 7 );
  NEON_ROUND( 8 );  NEON_ROUND( 9 );  NEON_ROUND( 10 ); NEON_ROUND( 11 );

  vst1q_u64(&S->h[0], veorq_u64(h0, veorq_u64(row1l, row3l)));
  vst1q_u64(&S->h[2], veorq_u64(h1, veorq_u64(row1h, row3h)));
  vst1q_u64(&S->h[4], veorq_u64(h2, veorq_u64(row2l, row4l)));
  vst1q_u64(&S->h[6], veorq_u64(h3, veorq_u64(row2h, row4h)));
  return 0;
}

/* ========================================================================
   blake2b_compress - Path 3: Portable scalar fallback
   ======================================================================== */
#else

static int blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
  uint64_t m[16];
  uint64_t v[16];
  int i;

  for( i = 0; i < 16; ++i )
    m[i] = load64( block + i * sizeof( m[i] ) );

  for( i = 0; i < 8; ++i )
    v[i] = S->h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = blake2b_IV[4] ^ S->t[0];
  v[13] = blake2b_IV[5] ^ S->t[1];
  v[14] = blake2b_IV[6] ^ S->f[0];
  v[15] = blake2b_IV[7] ^ S->f[1];

#define G(r,i,a,b,c,d)                      \
  do {                                       \
    a = a + b + m[blake2b_sigma[r][2*i+0]];  \
    d = rotr64(d ^ a, 32);                   \
    c = c + d;                               \
    b = rotr64(b ^ c, 24);                   \
    a = a + b + m[blake2b_sigma[r][2*i+1]];  \
    d = rotr64(d ^ a, 16);                   \
    c = c + d;                               \
    b = rotr64(b ^ c, 63);                   \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

  ROUND( 0 );  ROUND( 1 );  ROUND( 2 );  ROUND( 3 );
  ROUND( 4 );  ROUND( 5 );  ROUND( 6 );  ROUND( 7 );
  ROUND( 8 );  ROUND( 9 );  ROUND( 10 ); ROUND( 11 );

  for( i = 0; i < 8; ++i )
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
  return 0;
}

#endif /* compress path selection */

/* ========================================================================
   Common functions (shared by all paths)
   ======================================================================== */

int blake2b_init_param( blake2b_state *S, const blake2b_param *P )
{
  const uint8_t * v = ( const uint8_t * )( blake2b_IV );
  const uint8_t * p = ( const uint8_t * )( P );
  uint8_t * h = ( uint8_t * )( S->h );

  memset( S, 0, sizeof( blake2b_state ) );
  for( int i = 0; i < BLAKE2B_OUTBYTES; ++i ) h[i] = v[i] ^ p[i];
  return 0;
}

int blake2b_init( blake2b_state *S, const uint8_t outlen )
{
  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  const blake2b_param P =
  {
    outlen, 0, 1, 1, 0, 0, 0, 0, {0}, {0}, {0}
  };
  return blake2b_init_param( S, &P );
}

int blake2b_init_key( blake2b_state *S, const uint8_t outlen, const void *key, const uint8_t keylen )
{
  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;
  if ( ( !keylen ) || keylen > BLAKE2B_KEYBYTES ) return -1;

  const blake2b_param P =
  {
    outlen, keylen, 1, 1, 0, 0, 0, 0, {0}, {0}, {0}
  };

  if( blake2b_init_param( S, &P ) < 0 )
    return 0;

  {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset( block, 0, BLAKE2B_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2b_update( S, block, BLAKE2B_BLOCKBYTES );
    secure_zero_memory( block, BLAKE2B_BLOCKBYTES );
  }
  return 0;
}

int blake2b_update( blake2b_state *S, const uint8_t *in, uint64_t inlen )
{
  while( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = 2 * BLAKE2B_BLOCKBYTES - left;

    if( inlen > fill )
    {
      memcpy( S->buf + left, in, fill );
      S->buflen += fill;
      blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
      blake2b_compress( S, S->buf );
      memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, BLAKE2B_BLOCKBYTES );
      S->buflen -= BLAKE2B_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    }
    else
    {
      memcpy( S->buf + left, in, (size_t)inlen );
      S->buflen += (size_t)inlen;
      in += inlen;
      inlen -= inlen;
    }
  }
  return 0;
}

int blake2b_final( blake2b_state *S, uint8_t *out, uint8_t outlen )
{
  if( outlen > BLAKE2B_OUTBYTES )
    return -1;

  if( S->buflen > BLAKE2B_BLOCKBYTES )
  {
    blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
    blake2b_compress( S, S->buf );
    S->buflen -= BLAKE2B_BLOCKBYTES;
    memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, S->buflen );
  }

  blake2b_increment_counter( S, S->buflen );
  blake2b_set_lastblock( S );
  memset( S->buf + S->buflen, 0, 2 * BLAKE2B_BLOCKBYTES - S->buflen );
  blake2b_compress( S, S->buf );
  memcpy( out, &S->h[0], outlen );
  return 0;
}

int blake2b( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen )
{
  blake2b_state S[1];

  if ( NULL == in ) return -1;
  if ( NULL == out ) return -1;
  if( NULL == key ) keylen = 0;

  if( keylen )
  {
    if( blake2b_init_key( S, outlen, key, keylen ) < 0 ) return -1;
  }
  else
  {
    if( blake2b_init( S, outlen ) < 0 ) return -1;
  }

  blake2b_update( S, ( const uint8_t * )in, inlen );
  blake2b_final( S, out, outlen );
  return 0;
}

int blake2b_long(uint8_t *out, const void *in, const uint32_t outlen, const uint64_t inlen)
{
  blake2b_state blake_state;
  if (outlen <= BLAKE2B_OUTBYTES)
  {
    blake2b_init(&blake_state, (uint8_t)outlen);
    blake2b_update(&blake_state, (const uint8_t*)&outlen, sizeof(uint32_t));
    blake2b_update(&blake_state, (const uint8_t *)in, inlen);
    blake2b_final(&blake_state, out, (uint8_t)outlen);
  }
  else
  {
    uint8_t out_buffer[BLAKE2B_OUTBYTES];
    uint8_t in_buffer[BLAKE2B_OUTBYTES];
    blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
    blake2b_update(&blake_state, (const uint8_t*)&outlen, sizeof(uint32_t));
    blake2b_update(&blake_state, (const uint8_t *)in, inlen);
    blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);
    memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
    out += BLAKE2B_OUTBYTES / 2;
    uint32_t toproduce = outlen - BLAKE2B_OUTBYTES / 2;
    while (toproduce > BLAKE2B_OUTBYTES)
    {
      memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
      blake2b(out_buffer, in_buffer, NULL, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0);
      memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
      out += BLAKE2B_OUTBYTES / 2;
      toproduce -= BLAKE2B_OUTBYTES / 2;
    }
    memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
    blake2b(out_buffer, in_buffer, NULL, (uint8_t)toproduce, BLAKE2B_OUTBYTES, 0);
    memcpy(out, out_buffer, toproduce);
  }
  return 0;
}
