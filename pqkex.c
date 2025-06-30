/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <https://unlicense.org>
 *
 * Parts of this file have been compiled from other public domain implementations by DJB:
 * SHA512: https://gist.github.com/Sobieg/fd2bae95f62dac3f82862e86485c14b3
 * SNTRUP761: https://github.com/openssh/openssh-portable/blob/master/sntrup761.c
 * X25519: https://github.com/richfelker/bakelite/blob/main/x25519.c
 */

#ifdef NO_STD
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long int int64_t;
#else
#include <stdint.h>
#endif

#include "pqkex.h"

#define P 761
#define Q 4591
#define W 286
#define Q12 2295

typedef int8_t small;
typedef int16_t Fq;
typedef small Inputs[P];

extern void randombytes(void *buf, int count);
extern volatile int16_t crypto_int16_optblocker;
extern volatile int32_t crypto_int32_optblocker;
extern volatile int64_t crypto_int64_optblocker;

static inline uint64_t load_bigendian(const uint8_t *x) {
    return (uint64_t) (x[7]) | (((uint64_t) (x[6])) << 8) | (((uint64_t) (x[5])) << 16) | (((uint64_t) (x[4])) << 24) |
           (((uint64_t) (x[3])) << 32) | (((uint64_t) (x[2])) << 40) | (((uint64_t) (x[1])) << 48) |
           (((uint64_t) (x[0])) << 56);
}

static inline void store_bigendian(uint8_t *x, uint64_t u) {
    x[7] = u;
    u >>= 8;
    x[6] = u;
    u >>= 8;
    x[5] = u;
    u >>= 8;
    x[4] = u;
    u >>= 8;
    x[3] = u;
    u >>= 8;
    x[2] = u;
    u >>= 8;
    x[1] = u;
    u >>= 8;
    x[0] = u;
}

#define SHR(x, c) ((x) >> (c))
#define ROTR(x, c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define Sigma1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define sigma1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define M(w0, w14, w9, w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND                                                                                                                 \
    M(w0, w14, w9, w1)                                                                                                         \
    M(w1, w15, w10, w2)                                                                                                        \
    M(w2, w0, w11, w3)                                                                                                         \
    M(w3, w1, w12, w4)                                                                                                         \
    M(w4, w2, w13, w5)                                                                                                         \
    M(w5, w3, w14, w6)                                                                                                         \
    M(w6, w4, w15, w7)                                                                                                         \
    M(w7, w5, w0, w8)                                                                                                          \
    M(w8, w6, w1, w9)                                                                                                          \
    M(w9, w7, w2, w10)                                                                                                         \
    M(w10, w8, w3, w11)                                                                                                        \
    M(w11, w9, w4, w12)                                                                                                        \
    M(w12, w10, w5, w13)                                                                                                       \
    M(w13, w11, w6, w14)                                                                                                       \
    M(w14, w12, w7, w15)                                                                                                       \
    M(w15, w13, w8, w0)

#define F(w, k)                                                                                                                \
    T1 = h + Sigma1(e) + Ch(e, f, g) + k + w;                                                                                  \
    T2 = Sigma0(a) + Maj(a, b, c);                                                                                             \
    h = g;                                                                                                                     \
    g = f;                                                                                                                     \
    f = e;                                                                                                                     \
    e = d + T1;                                                                                                                \
    d = c;                                                                                                                     \
    c = b;                                                                                                                     \
    b = a;                                                                                                                     \
    a = T1 + T2;

static inline void sha512_hashblocks(uint8_t *statebytes, const uint8_t *in, uint64_t inlen) {
    uint64_t state[8];
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
    uint64_t T1;
    uint64_t T2;

    a = load_bigendian(statebytes + 0);
    state[0] = a;
    b = load_bigendian(statebytes + 8);
    state[1] = b;
    c = load_bigendian(statebytes + 16);
    state[2] = c;
    d = load_bigendian(statebytes + 24);
    state[3] = d;
    e = load_bigendian(statebytes + 32);
    state[4] = e;
    f = load_bigendian(statebytes + 40);
    state[5] = f;
    g = load_bigendian(statebytes + 48);
    state[6] = g;
    h = load_bigendian(statebytes + 56);
    state[7] = h;

    while (inlen >= 128) {
        uint64_t w0 = load_bigendian(in + 0);
        uint64_t w1 = load_bigendian(in + 8);
        uint64_t w2 = load_bigendian(in + 16);
        uint64_t w3 = load_bigendian(in + 24);
        uint64_t w4 = load_bigendian(in + 32);
        uint64_t w5 = load_bigendian(in + 40);
        uint64_t w6 = load_bigendian(in + 48);
        uint64_t w7 = load_bigendian(in + 56);
        uint64_t w8 = load_bigendian(in + 64);
        uint64_t w9 = load_bigendian(in + 72);
        uint64_t w10 = load_bigendian(in + 80);
        uint64_t w11 = load_bigendian(in + 88);
        uint64_t w12 = load_bigendian(in + 96);
        uint64_t w13 = load_bigendian(in + 104);
        uint64_t w14 = load_bigendian(in + 112);
        uint64_t w15 = load_bigendian(in + 120);

        F(w0, 0x428a2f98d728ae22ULL)
        F(w1, 0x7137449123ef65cdULL)
        F(w2, 0xb5c0fbcfec4d3b2fULL)
        F(w3, 0xe9b5dba58189dbbcULL)
        F(w4, 0x3956c25bf348b538ULL)
        F(w5, 0x59f111f1b605d019ULL)
        F(w6, 0x923f82a4af194f9bULL)
        F(w7, 0xab1c5ed5da6d8118ULL)
        F(w8, 0xd807aa98a3030242ULL)
        F(w9, 0x12835b0145706fbeULL)
        F(w10, 0x243185be4ee4b28cULL)
        F(w11, 0x550c7dc3d5ffb4e2ULL)
        F(w12, 0x72be5d74f27b896fULL)
        F(w13, 0x80deb1fe3b1696b1ULL)
        F(w14, 0x9bdc06a725c71235ULL)
        F(w15, 0xc19bf174cf692694ULL)

        EXPAND

        F(w0, 0xe49b69c19ef14ad2ULL)
        F(w1, 0xefbe4786384f25e3ULL)
        F(w2, 0x0fc19dc68b8cd5b5ULL)
        F(w3, 0x240ca1cc77ac9c65ULL)
        F(w4, 0x2de92c6f592b0275ULL)
        F(w5, 0x4a7484aa6ea6e483ULL)
        F(w6, 0x5cb0a9dcbd41fbd4ULL)
        F(w7, 0x76f988da831153b5ULL)
        F(w8, 0x983e5152ee66dfabULL)
        F(w9, 0xa831c66d2db43210ULL)
        F(w10, 0xb00327c898fb213fULL)
        F(w11, 0xbf597fc7beef0ee4ULL)
        F(w12, 0xc6e00bf33da88fc2ULL)
        F(w13, 0xd5a79147930aa725ULL)
        F(w14, 0x06ca6351e003826fULL)
        F(w15, 0x142929670a0e6e70ULL)

        EXPAND

        F(w0, 0x27b70a8546d22ffcULL)
        F(w1, 0x2e1b21385c26c926ULL)
        F(w2, 0x4d2c6dfc5ac42aedULL)
        F(w3, 0x53380d139d95b3dfULL)
        F(w4, 0x650a73548baf63deULL)
        F(w5, 0x766a0abb3c77b2a8ULL)
        F(w6, 0x81c2c92e47edaee6ULL)
        F(w7, 0x92722c851482353bULL)
        F(w8, 0xa2bfe8a14cf10364ULL)
        F(w9, 0xa81a664bbc423001ULL)
        F(w10, 0xc24b8b70d0f89791ULL)
        F(w11, 0xc76c51a30654be30ULL)
        F(w12, 0xd192e819d6ef5218ULL)
        F(w13, 0xd69906245565a910ULL)
        F(w14, 0xf40e35855771202aULL)
        F(w15, 0x106aa07032bbd1b8ULL)

        EXPAND

        F(w0, 0x19a4c116b8d2d0c8ULL)
        F(w1, 0x1e376c085141ab53ULL)
        F(w2, 0x2748774cdf8eeb99ULL)
        F(w3, 0x34b0bcb5e19b48a8ULL)
        F(w4, 0x391c0cb3c5c95a63ULL)
        F(w5, 0x4ed8aa4ae3418acbULL)
        F(w6, 0x5b9cca4f7763e373ULL)
        F(w7, 0x682e6ff3d6b2b8a3ULL)
        F(w8, 0x748f82ee5defb2fcULL)
        F(w9, 0x78a5636f43172f60ULL)
        F(w10, 0x84c87814a1f0ab72ULL)
        F(w11, 0x8cc702081a6439ecULL)
        F(w12, 0x90befffa23631e28ULL)
        F(w13, 0xa4506cebde82bde9ULL)
        F(w14, 0xbef9a3f7b2c67915ULL)
        F(w15, 0xc67178f2e372532bULL)

        EXPAND

        F(w0, 0xca273eceea26619cULL)
        F(w1, 0xd186b8c721c0c207ULL)
        F(w2, 0xeada7dd6cde0eb1eULL)
        F(w3, 0xf57d4f7fee6ed178ULL)
        F(w4, 0x06f067aa72176fbaULL)
        F(w5, 0x0a637dc5a2c898a6ULL)
        F(w6, 0x113f9804bef90daeULL)
        F(w7, 0x1b710b35131c471bULL)
        F(w8, 0x28db77f523047d84ULL)
        F(w9, 0x32caab7b40c72493ULL)
        F(w10, 0x3c9ebe0a15c9bebcULL)
        F(w11, 0x431d67c49c100d4cULL)
        F(w12, 0x4cc5d4becb3e42b6ULL)
        F(w13, 0x597f299cfc657e2aULL)
        F(w14, 0x5fcb6fab3ad6faecULL)
        F(w15, 0x6c44198c4a475817ULL)

        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 128;
        inlen -= 128;
    }

    store_bigendian(statebytes + 0, state[0]);
    store_bigendian(statebytes + 8, state[1]);
    store_bigendian(statebytes + 16, state[2]);
    store_bigendian(statebytes + 24, state[3]);
    store_bigendian(statebytes + 32, state[4]);
    store_bigendian(statebytes + 40, state[5]);
    store_bigendian(statebytes + 48, state[6]);
    store_bigendian(statebytes + 56, state[7]);
}

static const uint8_t sha512_iv[64] = {0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84,
                                      0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f,
                                      0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82,
                                      0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab,
                                      0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

static inline void crypto_hash_sha512(uint8_t *out, const uint8_t *in, uint64_t inlen) {
    uint8_t h[64];
    uint8_t padded[256];
    int i;
    uint64_t bytes = inlen;

    for (i = 0; i < 64; ++i)
        h[i] = sha512_iv[i];

    sha512_hashblocks(h, in, inlen);
    in += inlen;
    inlen &= 127;
    in -= inlen;

    for (i = 0; (uint64_t) i < inlen; ++i)
        padded[i] = in[i];
    padded[inlen] = 0x80;

    if (inlen < 112) {
        for (i = inlen + 1; i < 119; ++i)
            padded[i] = 0;
        padded[119] = bytes >> 61;
        padded[120] = bytes >> 53;
        padded[121] = bytes >> 45;
        padded[122] = bytes >> 37;
        padded[123] = bytes >> 29;
        padded[124] = bytes >> 21;
        padded[125] = bytes >> 13;
        padded[126] = bytes >> 5;
        padded[127] = bytes << 3;
        sha512_hashblocks(h, padded, 128);
    } else {
        for (i = inlen + 1; i < 247; ++i)
            padded[i] = 0;
        padded[247] = bytes >> 61;
        padded[248] = bytes >> 53;
        padded[249] = bytes >> 45;
        padded[250] = bytes >> 37;
        padded[251] = bytes >> 29;
        padded[252] = bytes >> 21;
        padded[253] = bytes >> 13;
        padded[254] = bytes >> 5;
        padded[255] = bytes << 3;
        sha512_hashblocks(h, padded, 256);
    }

    for (i = 0; i < 64; ++i)
        out[i] = h[i];
}

static inline int32_t crypto_int32_negative_mask(int32_t crypto_int32_x) {
#if defined(__GNUC__) && defined(__x86_64__)
    __asm__("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
    return crypto_int32_x;
#elif defined(__GNUC__) && defined(__aarch64__)
    int32_t crypto_int32_y;
    __asm__("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) :);
    return crypto_int32_y;
#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && !defined(__thumb__)
    int32_t crypto_int32_y;
    __asm__("asr %0,%1,#31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) :);
    return crypto_int32_y;
#elif defined(__GNUC__) && defined(__sparc_v8__)
    int32_t crypto_int32_y;
    __asm__("sra %1,31,%0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) :);
    return crypto_int32_y;
#else
    crypto_int32_x >>= 32 - 6;
    crypto_int32_x += crypto_int32_optblocker;
    crypto_int32_x >>= 5;
    return crypto_int32_x;
#endif
}

static inline int16_t crypto_int16_negative_mask(int16_t crypto_int16_x) {
#if defined(__GNUC__) && defined(__x86_64__)
    __asm__("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
    return crypto_int16_x;
#elif defined(__GNUC__) && defined(__aarch64__)
    int16_t crypto_int16_y;
    __asm__("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) :);
    return crypto_int16_y;
#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && !defined(__thumb__)
    int16_t crypto_int16_y;
    __asm__("sxth %0,%1\n asr %0,%0,#31" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) :);
    return crypto_int16_y;
#elif defined(__GNUC__) && defined(__sparc_v8__)
    int16_t crypto_int16_y;
    __asm__("sll %1,16,%0\n sra %0,31,%0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) :);
    return crypto_int16_y;
#else
    crypto_int16_x >>= 16 - 6;
    crypto_int16_x += crypto_int16_optblocker;
    crypto_int16_x >>= 5;
    return crypto_int16_x;
#endif
}

static inline int64_t crypto_int64_bottombit_01(int64_t crypto_int64_x) {
#if defined(__GNUC__) && defined(__x86_64__)
    __asm__("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
    return crypto_int64_x;
#elif defined(__GNUC__) && defined(__aarch64__)
    int64_t crypto_int64_y;
    __asm__("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) :);
    return crypto_int64_y;
#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && !defined(__thumb__)
    int64_t crypto_int64_y;
    __asm__("and %Q0,%Q1,#1\n mov %R0,#0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) :);
    return crypto_int64_y;
#elif defined(__GNUC__) && defined(__sparc_v8__)
    int64_t crypto_int64_y;
    __asm__("and %L1,1,%L0\n mov 0,%H0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) :);
    return crypto_int64_y;
#else
    crypto_int64_x &= 1 + crypto_int64_optblocker;
    return crypto_int64_x;
#endif
}

static inline int16_t crypto_int16_nonzero_mask(int16_t crypto_int16_x) {
#if defined(__GNUC__) && defined(__x86_64__)
    int16_t crypto_int16_q, crypto_int16_z;
    __asm__("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0"
            : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q)
            : "r"(crypto_int16_x)
            : "cc");
    return crypto_int16_z;
#elif defined(__GNUC__) && defined(__aarch64__)
    int16_t crypto_int16_z;
    __asm__("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
    return crypto_int16_z;
#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && !defined(__thumb__)
    __asm__("uxth %0,%0\n cmp %0,#0\n movne %0,#-1" : "+r"(crypto_int16_x) : : "cc");
    return crypto_int16_x;
#elif defined(__GNUC__) && defined(__sparc_v8__)
    int16_t crypto_int16_z;
    __asm__("sll %0,16,%0\n srl %0,16,%0\n cmp %%g0,%0\n subx %%g0,0,%1" : "+r"(crypto_int16_x), "=r"(crypto_int16_z) : : "cc");
    return crypto_int16_z;
#else
    crypto_int16_x |= -crypto_int16_x;
    return crypto_int16_negative_mask(crypto_int16_x);
#endif
}

static inline void crypto_int32_minmax(int32_t *crypto_int32_p, int32_t *crypto_int32_q) {
    int32_t crypto_int32_x = *crypto_int32_p;
    int32_t crypto_int32_y = *crypto_int32_q;
#if defined(__GNUC__) && defined(__x86_64__)
    int32_t crypto_int32_z;
    __asm__("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2"
            : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y)
            :
            : "cc");
    *crypto_int32_p = crypto_int32_x;
    *crypto_int32_q = crypto_int32_y;
#elif defined(__GNUC__) && defined(__aarch64__)
    int32_t crypto_int32_r, crypto_int32_s;
    __asm__("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt"
            : "=&r"(crypto_int32_r), "=r"(crypto_int32_s)
            : "r"(crypto_int32_x), "r"(crypto_int32_y)
            : "cc");
    *crypto_int32_p = crypto_int32_r;
    *crypto_int32_q = crypto_int32_s;
#else
    int64_t crypto_int32_r = (int64_t) crypto_int32_y ^ (int64_t) crypto_int32_x;
    int64_t crypto_int32_z = (int64_t) crypto_int32_y - (int64_t) crypto_int32_x;
    crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
    crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
    crypto_int32_z &= crypto_int32_r;
    crypto_int32_x ^= crypto_int32_z;
    crypto_int32_y ^= crypto_int32_z;
    *crypto_int32_p = crypto_int32_x;
    *crypto_int32_q = crypto_int32_y;
#endif
}

static inline int64_t crypto_int64_shrmod(int64_t crypto_int64_x, int64_t crypto_int64_s) {
#if defined(__GNUC__) && defined(__x86_64__)
    __asm__("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#elif defined(__GNUC__) && defined(__aarch64__)
    __asm__("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) :);
#else
    int crypto_int64_k, crypto_int64_l;
    for (crypto_int64_l = 0, crypto_int64_k = 1; crypto_int64_k < 64; ++crypto_int64_l, crypto_int64_k *= 2)
        crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) &
                          (-(((crypto_int64_s ^ crypto_int64_l ^ crypto_int64_optblocker) & 1) ^ crypto_int64_optblocker));
#endif
    return crypto_int64_x;
}

static inline int64_t crypto_int64_bitmod_01(int64_t crypto_int64_x, int64_t crypto_int64_s) {
    crypto_int64_x = crypto_int64_shrmod(crypto_int64_x, crypto_int64_s);
    return crypto_int64_bottombit_01(crypto_int64_x);
}

static inline void crypto_sort_int32(void *array, long long n) {
    long long top, p, q, r, i, j;
    int32_t *x = array;

    if (n < 2)
        return;
    top = 1;
    while (top < n - top)
        top += top;

    for (p = top; p >= 1; p >>= 1) {
        i = 0;
        while (i + 2 * p <= n) {
            for (j = i; j < i + p; ++j)
                crypto_int32_minmax(&x[j], &x[j + p]);
            i += 2 * p;
        }
        for (j = i; j < n - p; ++j)
            crypto_int32_minmax(&x[j], &x[j + p]);

        i = 0;
        j = 0;
        for (q = top; q > p; q >>= 1) {
            if (j != i)
                for (;;) {
                    if (j == n - q)
                        goto done;
                    int32_t a = x[j + p];
                    for (r = q; r > p; r >>= 1)
                        crypto_int32_minmax(&a, &x[j + r]);
                    x[j + p] = a;
                    ++j;
                    if (j == i + p) {
                        i += 2 * p;
                        break;
                    }
                }
            while (i + p <= n - q) {
                for (j = i; j < i + p; ++j) {
                    int32_t a = x[j + p];
                    for (r = q; r > p; r >>= 1)
                        crypto_int32_minmax(&a, &x[j + r]);
                    x[j + p] = a;
                }
                i += 2 * p;
            }
            /* now i + p > n - q */
            j = i;
            while (j < n - q) {
                int32_t a = x[j + p];
                for (r = q; r > p; r >>= 1)
                    crypto_int32_minmax(&a, &x[j + r]);
                x[j + p] = a;
                ++j;
            }

        done:;
        }
    }
}

static inline void crypto_sort_uint32(void *array, long long n) {
    uint32_t *x = array;
    long long j;
    for (j = 0; j < n; ++j)
        x[j] ^= 0x80000000;
    crypto_sort_int32(array, n);
    for (j = 0; j < n; ++j)
        x[j] ^= 0x80000000;
}

static inline void uint32_divmod_uint14(uint32_t *q, uint16_t *r, uint32_t x, uint16_t m) {
    uint32_t v = 0x80000000;
    uint32_t qpart;
    uint32_t mask;

    v /= m;
    *q = 0;
    qpart = (x * (uint64_t) v) >> 31;
    x -= qpart * m;
    *q += qpart;
    qpart = (x * (uint64_t) v) >> 31;
    x -= qpart * m;
    *q += qpart;
    x -= m;
    *q += 1;
    mask = crypto_int32_negative_mask(x);
    x += mask & (uint32_t) m;
    *q += mask;
    *r = x;
}

static inline uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
    uint32_t q;
    uint16_t r;
    uint32_divmod_uint14(&q, &r, x, m);
    return r;
}

static inline void Encode(unsigned char *out, const uint16_t *R, const uint16_t *M, long long len) {
    if (len == 1) {
        uint16_t r = R[0];
        uint16_t m = M[0];
        while (m > 1) {
            *out++ = r;
            r >>= 8;
            m = (m + 255) >> 8;
        }
    }
    if (len > 1) {
        uint16_t R2[(len + 1) / 2];
        uint16_t M2[(len + 1) / 2];
        long long i;
        for (i = 0; i < len - 1; i += 2) {
            uint32_t m0 = M[i];
            uint32_t r = R[i] + R[i + 1] * m0;
            uint32_t m = M[i + 1] * m0;
            while (m >= 16384) {
                *out++ = r;
                r >>= 8;
                m = (m + 255) >> 8;
            }
            R2[i / 2] = r;
            M2[i / 2] = m;
        }
        if (i < len) {
            R2[i / 2] = R[i];
            M2[i / 2] = M[i];
        }
        Encode(out, R2, M2, (len + 1) / 2);
    }
}

static inline void Decode(uint16_t *out, const unsigned char *S, const uint16_t *M, long long len) {
    if (len == 1) {
        if (M[0] == 1)
            *out = 0;
        else if (M[0] <= 256)
            *out = uint32_mod_uint14(S[0], M[0]);
        else
            *out = uint32_mod_uint14(S[0] + (((uint16_t) S[1]) << 8), M[0]);
    }
    if (len > 1) {
        uint16_t R2[(len + 1) / 2];
        uint16_t M2[(len + 1) / 2];
        uint16_t bottomr[len / 2];
        uint32_t bottomt[len / 2];
        long long i;
        for (i = 0; i < len - 1; i += 2) {
            uint32_t m = M[i] * (uint32_t) M[i + 1];
            if (m > 256 * 16383) {
                bottomt[i / 2] = 256 * 256;
                bottomr[i / 2] = S[0] + 256 * S[1];
                S += 2;
                M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
            } else if (m >= 16384) {
                bottomt[i / 2] = 256;
                bottomr[i / 2] = S[0];
                S += 1;
                M2[i / 2] = (m + 255) >> 8;
            } else {
                bottomt[i / 2] = 1;
                bottomr[i / 2] = 0;
                M2[i / 2] = m;
            }
        }
        if (i < len)
            M2[i / 2] = M[i];
        Decode(R2, S, M2, (len + 1) / 2);
        for (i = 0; i < len - 1; i += 2) {
            uint32_t r = bottomr[i / 2];
            uint32_t r1;
            uint16_t r0;
            r += bottomt[i / 2] * R2[i / 2];
            uint32_divmod_uint14(&r1, &r0, r, M[i]);
            r1 = uint32_mod_uint14(r1, M[i + 1]);
            *out++ = r0;
            *out++ = r1;
        }
        if (i < len)
            *out++ = R2[i / 2];
    }
}

static inline small F3_freeze(int16_t x) { return x - 3 * ((10923 * x + 16384) >> 15); }

static inline Fq Fq_freeze(int32_t x) {
    const int32_t q16 = (0x10000 + Q12) / Q;
    const int32_t q20 = (0x100000 + Q12) / Q;
    const int32_t q28 = (0x10000000 + Q12) / Q;
    x -= Q * ((q16 * x) >> 16);
    x -= Q * ((q20 * x) >> 20);
    return x - Q * ((q28 * x + 0x8000000) >> 28);
}

static inline Fq Fq_recip(Fq a1) {
    int i = 1;
    Fq ai = a1;
    while (i < Q - 2) {
        ai = Fq_freeze(a1 * (int32_t) ai);
        i += 1;
    }
    return ai;
}

static inline int Weightw_mask(small *r) {
    int i, weight = 0;
    for (i = 0; i < P; ++i)
        weight += crypto_int64_bottombit_01(r[i]);
    return crypto_int16_nonzero_mask(weight - W);
}

static inline void R3_fromRq(small *out, const Fq *r) {
    int i;
    for (i = 0; i < P; ++i)
        out[i] = F3_freeze(r[i]);
}

static inline void R3_mult(small *h, const small *f, const small *g) {
    int16_t fg[P + P - 1];
    int i, j;
    for (i = 0; i < P + P - 1; ++i)
        fg[i] = 0;
    for (i = 0; i < P; ++i)
        for (j = 0; j < P; ++j)
            fg[i + j] += f[i] * (int16_t) g[j];
    for (i = P; i < P + P - 1; ++i)
        fg[i - P] += fg[i];
    for (i = P; i < P + P - 1; ++i)
        fg[i - P + 1] += fg[i];
    for (i = 0; i < P; ++i)
        h[i] = F3_freeze(fg[i]);
}

static inline int R3_recip(small *out, const small *in) {
    small f[P + 1], g[P + 1], v[P + 1], r[P + 1];
    int sign, swap, t, i, loop, delta = 1;
    for (i = 0; i < P + 1; ++i)
        v[i] = 0;
    for (i = 0; i < P + 1; ++i)
        r[i] = 0;
    r[0] = 1;
    for (i = 0; i < P; ++i)
        f[i] = 0;
    f[0] = 1;
    f[P - 1] = f[P] = -1;
    for (i = 0; i < P; ++i)
        g[P - 1 - i] = in[i];
    g[P] = 0;
    for (loop = 0; loop < 2 * P - 1; ++loop) {
        for (i = P; i > 0; --i)
            v[i] = v[i - 1];
        v[0] = 0;
        sign = -g[0] * f[0];
        swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for (i = 0; i < P + 1; ++i) {
            t = swap & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            t = swap & (v[i] ^ r[i]);
            v[i] ^= t;
            r[i] ^= t;
        }
        for (i = 0; i < P + 1; ++i)
            g[i] = F3_freeze(g[i] + sign * f[i]);
        for (i = 0; i < P + 1; ++i)
            r[i] = F3_freeze(r[i] + sign * v[i]);
        for (i = 0; i < P; ++i)
            g[i] = g[i + 1];
        g[P] = 0;
    }
    sign = f[0];
    for (i = 0; i < P; ++i)
        out[i] = sign * v[P - 1 - i];
    return crypto_int16_nonzero_mask(delta);
}

static inline void Rq_mult_small(Fq *h, const Fq *f, const small *g) {
    int32_t fg[P + P - 1];
    int i, j;
    for (i = 0; i < P + P - 1; ++i)
        fg[i] = 0;
    for (i = 0; i < P; ++i)
        for (j = 0; j < P; ++j)
            fg[i + j] += f[i] * (int32_t) g[j];
    for (i = P; i < P + P - 1; ++i)
        fg[i - P] += fg[i];
    for (i = P; i < P + P - 1; ++i)
        fg[i - P + 1] += fg[i];
    for (i = 0; i < P; ++i)
        h[i] = Fq_freeze(fg[i]);
}

static inline void Rq_mult3(Fq *h, const Fq *f) {
    int i;
    for (i = 0; i < P; ++i)
        h[i] = Fq_freeze(3 * f[i]);
}

static inline int Rq_recip3(Fq *out, const small *in) {
    Fq f[P + 1], g[P + 1], v[P + 1], r[P + 1], scale;
    int swap, t, i, loop, delta = 1;
    int32_t f0, g0;
    for (i = 0; i < P + 1; ++i)
        v[i] = 0;
    for (i = 0; i < P + 1; ++i)
        r[i] = 0;
    r[0] = Fq_recip(3);
    for (i = 0; i < P; ++i)
        f[i] = 0;
    f[0] = 1;
    f[P - 1] = f[P] = -1;
    for (i = 0; i < P; ++i)
        g[P - 1 - i] = in[i];
    g[P] = 0;
    for (loop = 0; loop < 2 * P - 1; ++loop) {
        for (i = P; i > 0; --i)
            v[i] = v[i - 1];
        v[0] = 0;
        swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for (i = 0; i < P + 1; ++i) {
            t = swap & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            t = swap & (v[i] ^ r[i]);
            v[i] ^= t;
            r[i] ^= t;
        }
        f0 = f[0];
        g0 = g[0];
        for (i = 0; i < P + 1; ++i)
            g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
        for (i = 0; i < P + 1; ++i)
            r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
        for (i = 0; i < P; ++i)
            g[i] = g[i + 1];
        g[P] = 0;
    }
    scale = Fq_recip(f[0]);
    for (i = 0; i < P; ++i)
        out[i] = Fq_freeze(scale * (int32_t) v[P - 1 - i]);
    return crypto_int16_nonzero_mask(delta);
}

static inline void Round(Fq *out, const Fq *a) {
    int i;
    for (i = 0; i < P; ++i)
        out[i] = a[i] - F3_freeze(a[i]);
}

static inline void Short_fromlist(small *out, const uint32_t *in) {
    uint32_t L[P];
    int i;
    for (i = 0; i < W; ++i)
        L[i] = in[i] & (uint32_t) -2;
    for (i = W; i < P; ++i)
        L[i] = (in[i] & (uint32_t) -3) | 1;
    crypto_sort_uint32(L, P);
    for (i = 0; i < P; ++i)
        out[i] = (L[i] & 3) - 1;
}

static inline void Hash_prefix(unsigned char *out, int b, const unsigned char *in, int inlen) {
    unsigned char x[inlen + 1], h[64];
    int i;
    x[0] = b;
    for (i = 0; i < inlen; ++i)
        x[i + 1] = in[i];
    crypto_hash_sha512(h, x, inlen + 1);
    for (i = 0; i < 32; ++i)
        out[i] = h[i];
}

static inline uint32_t urandom32(void) {
    unsigned char c[4];
    uint32_t result = 0;
    int i;
    randombytes(c, 4);
    for (i = 0; i < 4; ++i)
        result += ((uint32_t) c[i]) << (8 * i);
    return result;
}

static inline void Short_random(small *out) {
    uint32_t L[P];
    int i;
    for (i = 0; i < P; ++i)
        L[i] = urandom32();
    Short_fromlist(out, L);
}

static inline void Small_random(small *out) {
    int i;
    for (i = 0; i < P; ++i)
        out[i] = (((urandom32() & 0x3fffffff) * 3) >> 30) - 1;
}

static inline void SKeyGen(Fq *h, small *f, small *ginv) {
    small g[P];
    Fq finv[P];
    for (;;) {
        int result;
        Small_random(g);
        result = R3_recip(ginv, g);
        if (result == 0)
            break;
    }
    Short_random(f);
    Rq_recip3(finv, f);
    Rq_mult_small(h, finv, g);
}

static inline void Encrypt(Fq *c, const small *r, const Fq *h) {
    Fq hr[P];
    Rq_mult_small(hr, h, r);
    Round(c, hr);
}

static inline void Decrypt(small *r, const Fq *c, const small *f, const small *ginv) {
    Fq cf[P], cf3[P];
    small e[P], ev[P];
    int mask, i;
    Rq_mult_small(cf, c, f);
    Rq_mult3(cf3, cf);
    R3_fromRq(e, cf3);
    R3_mult(ev, e, ginv);
    mask = Weightw_mask(ev);
    for (i = 0; i < W; ++i)
        r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
    for (i = W; i < P; ++i)
        r[i] = ev[i] & ~mask;
}

static inline void Small_encode(unsigned char *s, const small *f) {
    int i, j;
    for (i = 0; i < P / 4; ++i) {
        small x = 0;
        for (j = 0; j < 4; ++j)
            x += (*f++ + 1) << (2 * j);
        *s++ = x;
    }
    *s = *f++ + 1;
}

static inline void Small_decode(small *f, const unsigned char *s) {
    int i, j;
    for (i = 0; i < P / 4; ++i) {
        unsigned char x = *s++;
        for (j = 0; j < 4; ++j)
            *f++ = ((small) ((x >> (2 * j)) & 3)) - 1;
    }
    *f++ = ((small) (*s & 3)) - 1;
}

static inline void Rq_encode(unsigned char *s, const Fq *r) {
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i)
        R[i] = r[i] + Q12;
    for (i = 0; i < P; ++i)
        M[i] = Q;
    Encode(s, R, M, P);
}

static inline void Rq_decode(Fq *r, const unsigned char *s) {
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i)
        M[i] = Q;
    Decode(R, s, M, P);
    for (i = 0; i < P; ++i)
        r[i] = ((Fq) R[i]) - Q12;
}

static inline void Rounded_encode(unsigned char *s, const Fq *r) {
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i)
        R[i] = ((r[i] + Q12) * 10923) >> 15;
    for (i = 0; i < P; ++i)
        M[i] = (Q + 2) / 3;
    Encode(s, R, M, P);
}

static inline void Rounded_decode(Fq *r, const unsigned char *s) {
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i)
        M[i] = (Q + 2) / 3;
    Decode(R, s, M, P);
    for (i = 0; i < P; ++i)
        r[i] = R[i] * 3 - Q12;
}

static inline void ZKeyGen(unsigned char *pk, unsigned char *sk) {
    Fq h[P];
    small f[P], v[P];
    SKeyGen(h, f, v);
    Rq_encode(pk, h);
    Small_encode(sk, f);
    Small_encode(sk + 191, v);
}

static inline void ZEncrypt(unsigned char *C, const Inputs r, const unsigned char *pk) {
    Fq h[P], c[P];
    Rq_decode(h, pk);
    Encrypt(c, r, h);
    Rounded_encode(C, c);
}

static inline void ZDecrypt(Inputs r, const unsigned char *C, const unsigned char *sk) {
    small f[P], v[P];
    Fq c[P];
    Small_decode(f, sk);
    Small_decode(v, sk + 191);
    Rounded_decode(c, C);
    Decrypt(r, c, f, v);
}

static inline void HashConfirm(unsigned char *h, const unsigned char *r, const unsigned char *cache) {
    unsigned char x[64];
    int i;
    Hash_prefix(x, 3, r, 191);
    for (i = 0; i < 32; ++i)
        x[32 + i] = cache[i];
    Hash_prefix(h, 2, x, sizeof x);
}

static inline void HashSession(unsigned char *k, int b, const unsigned char *y, const unsigned char *z) {
    unsigned char x[1071];
    int i;
    Hash_prefix(x, 3, y, 191);
    for (i = 0; i < 1039; ++i)
        x[32 + i] = z[i];
    Hash_prefix(k, b, x, sizeof x);
}

static inline void KeyGen(unsigned char *pk, unsigned char *sk) {
    int i;
    ZKeyGen(pk, sk);
    sk += 382;
    for (i = 0; i < 1158; ++i)
        *sk++ = pk[i];
    randombytes(sk, 191);
    Hash_prefix(sk + 191, 4, pk, 1158);
}

static inline void Hide(unsigned char *c, unsigned char *r_enc, const Inputs r, const unsigned char *pk,
                        const unsigned char *cache) {
    Small_encode(r_enc, r);
    ZEncrypt(c, r, pk);
    HashConfirm(c + 1007, r_enc, cache);
}

static inline void Encaps(unsigned char *c, unsigned char *k, const unsigned char *pk) {
    Inputs r;
    unsigned char r_enc[191], cache[32];
    Hash_prefix(cache, 4, pk, 1158);
    Short_random(r);
    Hide(c, r_enc, r, pk, cache);
    HashSession(k, 1, r_enc, c);
}

static inline int Ciphertexts_diff_mask(const unsigned char *c, const unsigned char *c2) {
    uint16_t differentbits = 0;
    int len = 1039;
    while (len-- > 0)
        differentbits |= (*c++) ^ (*c2++);
    return (crypto_int64_bitmod_01((differentbits - 1), 8)) - 1;
}

static inline void Decaps(unsigned char *k, const unsigned char *c, const unsigned char *sk) {
    const unsigned char *pk = sk + 382;
    const unsigned char *rho = pk + 1158;
    const unsigned char *cache = rho + 191;
    Inputs r;
    unsigned char r_enc[191], cnew[1039];
    int mask, i;
    ZDecrypt(r, c, sk);
    Hide(cnew, r_enc, r, pk, cache);
    mask = Ciphertexts_diff_mask(c, cnew);
    for (i = 0; i < 191; ++i)
        r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
    HashSession(k, 1 + mask, r_enc, c);
}

typedef int64_t gf[16];

static const gf _121665 = {0xDB41, 1};

static inline void car25519(gf o) {
    int i;
    int64_t c;
    for (i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static inline void sel25519(gf p, gf q, int b) {
    int64_t t, i, c = ~(b - 1);
    for (i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static inline void pack25519(uint8_t *o, const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; ++i)
        t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; ++i) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

static inline void unpack25519(gf o, const uint8_t *n) {
    int i;
    for (i = 0; i < 16; ++i)
        o[i] = n[2 * i] + ((int64_t) n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static inline void gf_add(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; ++i)
        o[i] = a[i] + b[i];
}

static inline void gf_sub(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; ++i)
        o[i] = a[i] - b[i];
}

static inline void gf_mul(gf o, const gf a, const gf b) {
    int64_t i, j, t[31];
    for (i = 0; i < 31; ++i)
        t[i] = 0;
    for (i = 0; i < 16; ++i)
        for (j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; ++i)
        t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; ++i)
        o[i] = t[i];
    car25519(o);
    car25519(o);
}

static inline void gf_sqr(gf o, const gf a) { gf_mul(o, a, a); }

static inline void inv25519(gf o, const gf i) {
    gf c;
    int a;
    for (a = 0; a < 16; ++a)
        c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        gf_sqr(c, c);
        if (a != 2 && a != 4)
            gf_mul(c, c, i);
    }
    for (a = 0; a < 16; ++a)
        o[a] = c[a];
}

static inline void x25519_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    uint8_t z[32];
    int64_t x[80], r, i;
    gf a, b, c, d, e, f;
    for (i = 0; i < 31; ++i)
        z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sqr(d, e);
        gf_sqr(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sqr(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, _121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sqr(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    for (i = 0; i < 16; ++i) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv25519(x + 32, x + 32);
    gf_mul(x + 16, x + 16, x + 32);
    pack25519(q, x + 16);
}

static inline void memset(uint8_t *buf, uint8_t val, int count) {
    for (int i = 0; i < count; i++) {
        *buf++ = val;
    }
}

void pqkex_keygen(void *pub, void *priv) {
    memset(pub, 0, PQKEX_PKSIZE);
    memset(priv, 0, PQKEX_SKSIZE);

    uint8_t base[32] = {9};
    randombytes(priv, 32);
    x25519_scalarmult(pub, priv, base);

    pub = ((uint8_t *) pub) + 32;
    priv = ((uint8_t *) priv) + 32;

    KeyGen(pub, priv);
}

void pqkex_encaps(void *pub, void *ct, void *key) {
    memset(ct, 0, PQKEX_CTSIZE);
    memset(key, 0, PQKEX_SSSIZE);

    uint8_t base[32] = {9};
    uint8_t point[64];
    uint8_t pk[32];
    memset(point, 0, 64);

    randombytes(pk, 32);
    x25519_scalarmult(point, pk, pub);
    x25519_scalarmult(ct, pk, base);

    pub = ((uint8_t *) pub) + 32;
    ct = ((uint8_t *) ct) + 32;

    Encaps(ct, &point[32], pub);

    crypto_hash_sha512(key, point, 64);
}

void pqkex_decaps(void *priv, void *ct, void *key) {
    memset(key, 0, PQKEX_SSSIZE);

    uint8_t point[64];
    memset(point, 0, 64);
    x25519_scalarmult(point, priv, ct);

    priv = ((uint8_t *) priv) + 32;
    ct = ((uint8_t *) ct) + 32;

    Decaps(&point[32], ct, priv);

    crypto_hash_sha512(key, point, 64);
}
