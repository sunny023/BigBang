#include <x86intrin.h>
/*
static void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    *x0 = _mm_aesenc_si128(*x0, key);
    *x1 = _mm_aesenc_si128(*x1, key);
    *x2 = _mm_aesenc_si128(*x2, key);
    *x3 = _mm_aesenc_si128(*x3, key);
    *x4 = _mm_aesenc_si128(*x4, key);
    *x5 = _mm_aesenc_si128(*x5, key);
    *x6 = _mm_aesenc_si128(*x6, key);
    *x7 = _mm_aesenc_si128(*x7, key);
}*/

#include "cnbbc/cn/Algorithm.h"
#include "cnbbc/cn/CnAlgo.h"
#include "cnbbc/cn/CnCtx.h"
#include "cnbbc/cn/CryptoNight.h"
#include "cnbbc/cn/CryptoNight_monero.h"
#include "cnbbc/cn/VirtualMemory.h"
#include "cnbbc/cn/keccak.h"

extern "C"
{
#include "cnbbc/cn/c_blake256.h"
#include "cnbbc/cn/c_groestl.h"
#include "cnbbc/cn/c_jh.h"
#include "cnbbc/cn/c_skein.h"
}
#include <chrono>
#include <iostream>

#include "cnbbc/cn/CnHash.h"
#include "cnbbc/cn/soft_aes.h"

namespace xmrig
{

static inline void do_blake_hash(const uint8_t* input, size_t len, uint8_t* output)
{
    blake256_hash(output, input, len);
}

static inline void do_groestl_hash(const uint8_t* input, size_t len, uint8_t* output)
{
    groestl(input, len * 8, output);
}

static inline void do_jh_hash(const uint8_t* input, size_t len, uint8_t* output)
{
    jh_hash(32 * 8, input, 8 * len, output);
}

static inline void do_skein_hash(const uint8_t* input, size_t len, uint8_t* output)
{
    xmr_skein(input, output);
}

void (*const extra_hashes[4])(const uint8_t*, size_t, uint8_t*) = { do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash };

static inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
    __m128i tmp0 = x0;
    x0 = _mm_xor_si128(x0, x1);
    x1 = _mm_xor_si128(x1, x2);
    x2 = _mm_xor_si128(x2, x3);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_xor_si128(x4, x5);
    x5 = _mm_xor_si128(x5, x6);
    x6 = _mm_xor_si128(x6, x7);
    x7 = _mm_xor_si128(x7, tmp0);
}

static void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    *x0 = _mm_aesenc_si128(*x0, key);
    *x1 = _mm_aesenc_si128(*x1, key);
    *x2 = _mm_aesenc_si128(*x2, key);
    *x3 = _mm_aesenc_si128(*x3, key);
    *x4 = _mm_aesenc_si128(*x4, key);
    *x5 = _mm_aesenc_si128(*x5, key);
    *x6 = _mm_aesenc_si128(*x6, key);
    *x7 = _mm_aesenc_si128(*x7, key);
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}

template <uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
    xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1 = _mm_aeskeygenassist_si128(*xout0, 0x00);
    xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}

template <uint8_t rcon>
static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
    xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1 = soft_aeskeygenassist<0x00>(*xout0);
    xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}

template <bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0 = _mm_load_si128(memory);
    __m128i xout2 = _mm_load_si128(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x01>(&xout0, &xout2) : aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x02>(&xout0, &xout2) : aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x04>(&xout0, &xout2) : aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x08>(&xout0, &xout2) : aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}

template <Algorithm::Id ALGO, bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
    constexpr CnAlgo<ALGO> props;

    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    if (props.isHeavy())
    {
        for (size_t i = 0; i < 16; i++)
        {
            aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

            mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
        }
    }

    for (size_t i = 0; i < props.memory() / sizeof(__m128i); i += 8)
    {
        aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(output + i + 0, xin0);
        _mm_store_si128(output + i + 1, xin1);
        _mm_store_si128(output + i + 2, xin2);
        _mm_store_si128(output + i + 3, xin3);
        _mm_store_si128(output + i + 4, xin4);
        _mm_store_si128(output + i + 5, xin5);
        _mm_store_si128(output + i + 6, xin6);
        _mm_store_si128(output + i + 7, xin7);
    }
}

static inline __m128i aes_round_tweak_div(const __m128i& in, const __m128i& key)
{
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];

    _mm_store_si128((__m128i*)k, key);
    _mm_store_si128((__m128i*)x, _mm_xor_si128(in, _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff)));

#define BYTE(p, i) ((unsigned char*)&x[p])[i]
    k[0] ^= saes_table[0][BYTE(0, 0)] ^ saes_table[1][BYTE(1, 1)] ^ saes_table[2][BYTE(2, 2)] ^ saes_table[3][BYTE(3, 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(1, 0)] ^ saes_table[1][BYTE(2, 1)] ^ saes_table[2][BYTE(3, 2)] ^ saes_table[3][BYTE(0, 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(2, 0)] ^ saes_table[1][BYTE(3, 1)] ^ saes_table[2][BYTE(0, 2)] ^ saes_table[3][BYTE(1, 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(3, 0)] ^ saes_table[1][BYTE(0, 1)] ^ saes_table[2][BYTE(1, 2)] ^ saes_table[3][BYTE(2, 3)];
#undef BYTE

    return _mm_load_si128((__m128i*)k);
}

static inline __m128i int_sqrt_v2(const uint64_t n0)
{
    __m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(n0 >> 12), _mm_set_epi64x(0, 1023ULL << 52)));
    x = _mm_sqrt_sd(_mm_setzero_pd(), x);
    uint64_t r = static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_castpd_si128(x)));

    const uint64_t s = r >> 20;
    r >>= 19;

    uint64_t x2 = (s - (1022ULL << 32)) * (r - s - (1022ULL << 32) + 1);
#if (defined(_MSC_VER) || __GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ > 1)) && (defined(__x86_64__) || defined(_M_AMD64))
    _addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned long long int*)&x2), r, 0, (unsigned long long int*)&r);
#else
    if (x2 < n0)
        ++r;
#endif

    return _mm_cvtsi64_si128(r);
}

template <Algorithm::Id ALGO>
static inline void cryptonight_monero_tweak(uint64_t* mem_out, const uint8_t* l, uint64_t idx, __m128i ax0, __m128i bx0, __m128i bx1, __m128i& cx)
{
    constexpr CnAlgo<ALGO> props;

    if (props.base() == Algorithm::CN_2)
    {
        VARIANT2_SHUFFLE(l, idx, ax0, bx0, bx1, cx, (ALGO == Algorithm::CN_RWZ ? 1 : 0));
        _mm_store_si128(reinterpret_cast<__m128i*>(mem_out), _mm_xor_si128(bx0, cx));
    }
    else
    {
        __m128i tmp = _mm_xor_si128(bx0, cx);
        mem_out[0] = _mm_cvtsi128_si64(tmp);

        tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
        uint64_t vh = _mm_cvtsi128_si64(tmp);

        uint8_t x = static_cast<uint8_t>(vh >> 24);
        static const uint16_t table = 0x7531;
        const uint8_t index = (((x >> (3)) & 6) | (x & 1)) << 1;
        vh ^= ((table >> index) & 0x3) << 28;

        mem_out[1] = vh;
    }
}

template <Algorithm::Id ALGO, bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
    constexpr CnAlgo<ALGO> props;

#ifdef XMRIG_ALGO_CN_GPU
    constexpr bool IS_HEAVY = props.isHeavy() || ALGO == Algorithm::CN_GPU;
#else
    constexpr bool IS_HEAVY = props.isHeavy();
#endif

    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    for (size_t i = 0; i < props.memory() / sizeof(__m128i); i += 8)
    {
        xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
        xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

        aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

        if (IS_HEAVY)
        {
            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    if (IS_HEAVY)
    {
        for (size_t i = 0; i < props.memory() / sizeof(__m128i); i += 8)
        {
            xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
            xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
            xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
            xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
            xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
            xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
            xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
            xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

            aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }

        for (size_t i = 0; i < 16; i++)
        {
            aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}

static inline uint64_t __umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi)
{
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = multiplier >> 32;
    uint64_t b = multiplier & 0xFFFFFFFF;
    uint64_t c = multiplicand >> 32;
    uint64_t d = multiplicand & 0xFFFFFFFF;

    //uint64_t ac = a * c;
    uint64_t ad = a * d;
    //uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + (b * c);
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    return product_lo;
}

template <Algorithm::Id ALGO, bool SOFT_AES>
void cryptonight_single_hash(const uint8_t* __restrict__ input, size_t size, uint8_t* __restrict__ output, cryptonight_ctx** __restrict__ ctx, uint64_t height)
{
    using namespace xmrig;

    constexpr CnAlgo<ALGO> props;
    constexpr size_t MASK = props.mask();
    constexpr Algorithm::Id BASE = props.base();

    constexpr bool IS_CN_HEAVY_TUBE = false;

    keccak(input, size, ctx[0]->state);
    for (int i = 0; i < 2000; i++)
    {
        keccak(ctx[0]->state, 128, ctx[0]->state);
    }
    cn_explode_scratchpad<ALGO, SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[0]->state), reinterpret_cast<__m128i*>(ctx[0]->memory));

    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint8_t* l0 = ctx[0]->memory;

    VARIANT1_INIT(0);
    VARIANT2_INIT(0);
    //BBC_INIT();
    __m128i _c_aes;
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t idx0 = al0;
    __m128i bx0 = _mm_set_epi64x(static_cast<int64_t>(h0[3] ^ h0[7]), static_cast<int64_t>(h0[2] ^ h0[6]));
    __m128i bx1 = _mm_set_epi64x(static_cast<int64_t>(h0[9] ^ h0[11]), static_cast<int64_t>(h0[8] ^ h0[10]));
    for (size_t i = 0; i < props.iterations(); i++)
    {
        __m128i cx;
        if (IS_CN_HEAVY_TUBE || !SOFT_AES)
        {
            cx = _mm_load_si128(reinterpret_cast<const __m128i*>(&l0[idx0 & MASK]));
        }

        const __m128i ax0 = _mm_set_epi64x(static_cast<int64_t>(ah0), static_cast<int64_t>(al0));
        //BBC_PRE_AES();

        cx = _mm_aesenc_si128(cx, ax0);

        _c_aes = cx;
        for (int j = 0; j < 27; j++)
        {
            _c_aes = _mm_aesenc_si128(_c_aes, _c_aes);
        }

        if (BASE == Algorithm::CN_1 || BASE == Algorithm::CN_2)
        {
            cryptonight_monero_tweak<ALGO>(reinterpret_cast<uint64_t*>(&l0[idx0 & MASK]), l0, idx0 & MASK, ax0, bx0, bx1, cx);
        }
        else
        {
            _mm_store_si128(reinterpret_cast<__m128i*>(&l0[idx0 & MASK]), _mm_xor_si128(bx0, cx));
        }

        idx0 = static_cast<uint64_t>(_mm_cvtsi128_si64(cx));

        uint64_t hi, lo, cl, ch;
        cl = (reinterpret_cast<uint64_t*>(&l0[idx0 & MASK]))[0];
        ch = (reinterpret_cast<uint64_t*>(&l0[idx0 & MASK]))[1];

        if (BASE == Algorithm::CN_2)
        {
            VARIANT2_INTEGER_MATH(0, cl, cx);
        }

        lo = __umul128(idx0, cl, &hi);

        if (BASE == Algorithm::CN_2)
        {
            if (ALGO == Algorithm::CN_R)
            {
                VARIANT2_SHUFFLE(l0, idx0 & MASK, ax0, bx0, bx1, cx, 0);
            }
            else
            {
                VARIANT2_SHUFFLE2(l0, idx0 & MASK, ax0, bx0, bx1, hi, lo, (ALGO == Algorithm::CN_RWZ ? 1 : 0));
            }
        }

        al0 += hi;
        ah0 += lo;

        reinterpret_cast<uint64_t*>(&l0[idx0 & MASK])[0] = al0;

        if (IS_CN_HEAVY_TUBE || ALGO == Algorithm::CN_RTO)
        {
            reinterpret_cast<uint64_t*>(&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0 ^ al0;
        }
        else if (BASE == Algorithm::CN_1)
        {
            reinterpret_cast<uint64_t*>(&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0;
        }
        else
        {
            reinterpret_cast<uint64_t*>(&l0[idx0 & MASK])[1] = ah0;
        }

        al0 ^= cl;
        ah0 ^= ch;

        al0 ^= ((uint64_t*)(&_c_aes))[0];
        ah0 ^= ((uint64_t*)uint64_t(&_c_aes))[1];
        //BBC_PPOST_AES();

        idx0 = al0;

        if (BASE == Algorithm::CN_2)
        {
            bx1 = bx0;
        }

        bx0 = cx;
    }

    cn_implode_scratchpad<ALGO, SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[0]->memory), reinterpret_cast<__m128i*>(ctx[0]->state));
    keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}

} // namespace xmrig

static const size_t max_mem_size = 4 * 1024 * 1024;
static struct cryptonight_ctx* ctx = nullptr;
static xmrig::VirtualMemory mem(max_mem_size, true, 4096);

void cn_sse_hash(const void* data, size_t length, char* hash)
{
    if (ctx == nullptr)
    {
        xmrig::CnCtx::create(&ctx, mem.scratchpad(), max_mem_size, 1);
    }
    xmrig::cryptonight_single_hash<xmrig::Algorithm::CN_BBC, false>((uint8_t*)data, length, (uint8_t*)hash, &ctx, 0);
}

extern "C" void cn_slow_hash(const void* data, size_t length, char* hash, int variant, int prehashed, uint64_t height);

void Test_CN_BBC()
{
    for (int j = 0; j < 10; j++)
    {
        uint8_t test_input[32] = { 0 };
        for (uint32_t i = 0; i < sizeof(test_input); i++)
        {
            test_input[i] = i + j;
        }
        uint8_t output1[32] = { 0 };
        uint8_t output2[32] = { 0 };

        cn_sse_hash(test_input, sizeof(test_input), (char*)output1);
        cn_slow_hash(test_input, sizeof(test_input), (char*)output2, 2, 0, 0);
        if (*(int*)output1 == *(int*)output2)
        {
            printf("OK: %d \n", *(int*)output1);
        }
        else
        {
            printf("Err: %d \n", *(int*)output1);
        }
    }
}