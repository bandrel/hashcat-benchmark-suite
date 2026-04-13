// ntlm_md4.metal — Native Metal compute shader for NTLM (MD4) hashing
// Matches hashcat's a3-optimized kernel architecture:
//   - Inner loop over IL_CNT candidates per thread
//   - 48-constant precomputation outside the loop (scalar)
//   - Only w[0] varies per iteration
//   - Vec:1 and Vec:2 variants

#include <metal_stdlib>
using namespace metal;

// MD4 initial values
constant uint MD4M_A = 0x67452301u;
constant uint MD4M_B = 0xefcdab89u;
constant uint MD4M_C = 0x98badcfeu;
constant uint MD4M_D = 0x10325476u;

// Round constants
constant uint MD4C00 = 0x00000000u;
constant uint MD4C01 = 0x5a827999u;
constant uint MD4C02 = 0x6ed9eba1u;

// Round functions (non-select — matches Apple Silicon's current path)
inline uint MD4_F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
inline uint MD4_G(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
inline uint MD4_H(uint x, uint y, uint z) { return x ^ y ^ z; }

// MD4 step macros
// MD4_STEP: used for steps involving the varying word w0 (adds w0 as separate operand)
#define MD4_STEP(f, a, b, c, d, w, precomp, s) \
    do { (a) = (a) + (precomp) + (w) + f((b),(c),(d)); (a) = rotate((a), (uint)(s)); } while(0)

// MD4_STEP0: used for steps with precomputed (w[i] + constant) — no separate word operand
#define MD4_STEP0(f, a, b, c, d, precomp, s) \
    do { (a) = (a) + (precomp) + f((b),(c),(d)); (a) = rotate((a), (uint)(s)); } while(0)

// Shift amounts
constant uint S00=3,S01=7,S02=11,S03=19;
constant uint S10=3,S11=5,S12=9,S13=13;
constant uint S20=3,S21=9,S22=11,S23=15;

// UTF-16LE expansion helper
inline uint make_utf16le(uint v) {
    return (v & 0xFFu) | ((v & 0xFF00u) << 8u);
}

// ============================================================================
// Vec:1 kernel — matches hashcat's a3-optimized m01000m architecture
//
// Each thread:
//   1. Loads base password words w[0..15] (already UTF-16LE expanded + padded)
//   2. Precomputes 48 scalar constants: w[i] + MD4C0x
//   3. Loops over IL_CNT iterations, varying only w[0]
//   4. Per iteration: w0 = w0_left | words_buf_r[il_pos]
//
// Buffers:
//   base_words:  [num_threads][16] — base password words per thread
//   words_buf_r: [IL_CNT]         — right-side varying bits per iteration
//   digests:     [num_threads * IL_CNT] — output (or just count matches)
// ============================================================================
kernel void ntlm_bench_v1(
    device const uint*  base_words   [[buffer(0)]],   // [num_threads * 16]
    device const uint*  words_buf_r  [[buffer(1)]],   // [IL_CNT]
    device       uint4* digests      [[buffer(2)]],   // [num_threads * IL_CNT]
    constant     uint&  il_cnt       [[buffer(3)]],   // inner loop count
    uint                gid          [[thread_position_in_grid]])
{
    // Load base password words for this thread
    uint w1  = base_words[gid * 16 +  1];
    uint w2  = base_words[gid * 16 +  2];
    uint w3  = base_words[gid * 16 +  3];
    uint w4  = base_words[gid * 16 +  4];
    uint w5  = base_words[gid * 16 +  5];
    uint w6  = base_words[gid * 16 +  6];
    uint w7  = base_words[gid * 16 +  7];
    uint w8  = base_words[gid * 16 +  8];
    uint w9  = base_words[gid * 16 +  9];
    uint wa  = base_words[gid * 16 + 10];
    uint wb  = base_words[gid * 16 + 11];
    uint wc  = base_words[gid * 16 + 12];
    uint wd  = base_words[gid * 16 + 13];
    uint we  = base_words[gid * 16 + 14];
    uint wf  = base_words[gid * 16 + 15];
    uint w0l = base_words[gid * 16 +  0];

    // Precompute 48 constants (scalar, outside the loop)
    const uint F_w0c00 =    0 + MD4C00;
    const uint F_w1c00 = w1   + MD4C00;
    const uint F_w2c00 = w2   + MD4C00;
    const uint F_w3c00 = w3   + MD4C00;
    const uint F_w4c00 = w4   + MD4C00;
    const uint F_w5c00 = w5   + MD4C00;
    const uint F_w6c00 = w6   + MD4C00;
    const uint F_w7c00 = w7   + MD4C00;
    const uint F_w8c00 = w8   + MD4C00;
    const uint F_w9c00 = w9   + MD4C00;
    const uint F_wac00 = wa   + MD4C00;
    const uint F_wbc00 = wb   + MD4C00;
    const uint F_wcc00 = wc   + MD4C00;
    const uint F_wdc00 = wd   + MD4C00;
    const uint F_wec00 = we   + MD4C00;
    const uint F_wfc00 = wf   + MD4C00;

    const uint G_w0c01 =    0 + MD4C01;
    const uint G_w4c01 = w4   + MD4C01;
    const uint G_w8c01 = w8   + MD4C01;
    const uint G_wcc01 = wc   + MD4C01;
    const uint G_w1c01 = w1   + MD4C01;
    const uint G_w5c01 = w5   + MD4C01;
    const uint G_w9c01 = w9   + MD4C01;
    const uint G_wdc01 = wd   + MD4C01;
    const uint G_w2c01 = w2   + MD4C01;
    const uint G_w6c01 = w6   + MD4C01;
    const uint G_wac01 = wa   + MD4C01;
    const uint G_wec01 = we   + MD4C01;
    const uint G_w3c01 = w3   + MD4C01;
    const uint G_w7c01 = w7   + MD4C01;
    const uint G_wbc01 = wb   + MD4C01;
    const uint G_wfc01 = wf   + MD4C01;

    const uint H_w0c02 =    0 + MD4C02;
    const uint H_w8c02 = w8   + MD4C02;
    const uint H_w4c02 = w4   + MD4C02;
    const uint H_wcc02 = wc   + MD4C02;
    const uint H_w2c02 = w2   + MD4C02;
    const uint H_wac02 = wa   + MD4C02;
    const uint H_w6c02 = w6   + MD4C02;
    const uint H_wec02 = we   + MD4C02;
    const uint H_w1c02 = w1   + MD4C02;
    const uint H_w9c02 = w9   + MD4C02;
    const uint H_w5c02 = w5   + MD4C02;
    const uint H_wdc02 = wd   + MD4C02;
    const uint H_w3c02 = w3   + MD4C02;
    const uint H_wbc02 = wb   + MD4C02;
    const uint H_w7c02 = w7   + MD4C02;
    const uint H_wfc02 = wf   + MD4C02;

    // Inner loop — matches hashcat's IL_CNT loop
    // Like hashcat's COMPARE_M_SIMD, we don't write every digest.
    // Instead we accumulate a checksum to prevent dead-code elimination.
    uint4 acc = uint4(0);

    for (uint il_pos = 0; il_pos < il_cnt; il_pos++) {
        const uint w0r = words_buf_r[il_pos];
        const uint w0  = w0l | w0r;

        uint a = MD4M_A;
        uint b = MD4M_B;
        uint c = MD4M_C;
        uint d = MD4M_D;

        // Round 1 — F
        MD4_STEP (MD4_F, a,b,c,d, w0, F_w0c00, S00);
        MD4_STEP0(MD4_F, d,a,b,c,     F_w1c00, S01);
        MD4_STEP0(MD4_F, c,d,a,b,     F_w2c00, S02);
        MD4_STEP0(MD4_F, b,c,d,a,     F_w3c00, S03);
        MD4_STEP0(MD4_F, a,b,c,d,     F_w4c00, S00);
        MD4_STEP0(MD4_F, d,a,b,c,     F_w5c00, S01);
        MD4_STEP0(MD4_F, c,d,a,b,     F_w6c00, S02);
        MD4_STEP0(MD4_F, b,c,d,a,     F_w7c00, S03);
        MD4_STEP0(MD4_F, a,b,c,d,     F_w8c00, S00);
        MD4_STEP0(MD4_F, d,a,b,c,     F_w9c00, S01);
        MD4_STEP0(MD4_F, c,d,a,b,     F_wac00, S02);
        MD4_STEP0(MD4_F, b,c,d,a,     F_wbc00, S03);
        MD4_STEP0(MD4_F, a,b,c,d,     F_wcc00, S00);
        MD4_STEP0(MD4_F, d,a,b,c,     F_wdc00, S01);
        MD4_STEP0(MD4_F, c,d,a,b,     F_wec00, S02);
        MD4_STEP0(MD4_F, b,c,d,a,     F_wfc00, S03);

        // Round 2 — G
        MD4_STEP (MD4_G, a,b,c,d, w0, G_w0c01, S10);
        MD4_STEP0(MD4_G, d,a,b,c,     G_w4c01, S11);
        MD4_STEP0(MD4_G, c,d,a,b,     G_w8c01, S12);
        MD4_STEP0(MD4_G, b,c,d,a,     G_wcc01, S13);
        MD4_STEP0(MD4_G, a,b,c,d,     G_w1c01, S10);
        MD4_STEP0(MD4_G, d,a,b,c,     G_w5c01, S11);
        MD4_STEP0(MD4_G, c,d,a,b,     G_w9c01, S12);
        MD4_STEP0(MD4_G, b,c,d,a,     G_wdc01, S13);
        MD4_STEP0(MD4_G, a,b,c,d,     G_w2c01, S10);
        MD4_STEP0(MD4_G, d,a,b,c,     G_w6c01, S11);
        MD4_STEP0(MD4_G, c,d,a,b,     G_wac01, S12);
        MD4_STEP0(MD4_G, b,c,d,a,     G_wec01, S13);
        MD4_STEP0(MD4_G, a,b,c,d,     G_w3c01, S10);
        MD4_STEP0(MD4_G, d,a,b,c,     G_w7c01, S11);
        MD4_STEP0(MD4_G, c,d,a,b,     G_wbc01, S12);
        MD4_STEP0(MD4_G, b,c,d,a,     G_wfc01, S13);

        // Round 3 — H
        MD4_STEP (MD4_H, a,b,c,d, w0, H_w0c02, S20);
        MD4_STEP0(MD4_H, d,a,b,c,     H_w8c02, S21);
        MD4_STEP0(MD4_H, c,d,a,b,     H_w4c02, S22);
        MD4_STEP0(MD4_H, b,c,d,a,     H_wcc02, S23);
        MD4_STEP0(MD4_H, a,b,c,d,     H_w2c02, S20);
        MD4_STEP0(MD4_H, d,a,b,c,     H_wac02, S21);
        MD4_STEP0(MD4_H, c,d,a,b,     H_w6c02, S22);
        MD4_STEP0(MD4_H, b,c,d,a,     H_wec02, S23);
        MD4_STEP0(MD4_H, a,b,c,d,     H_w1c02, S20);
        MD4_STEP0(MD4_H, d,a,b,c,     H_w9c02, S21);
        MD4_STEP0(MD4_H, c,d,a,b,     H_w5c02, S22);
        MD4_STEP0(MD4_H, b,c,d,a,     H_wdc02, S23);
        MD4_STEP0(MD4_H, a,b,c,d,     H_w3c02, S20);
        MD4_STEP0(MD4_H, d,a,b,c,     H_wbc02, S21);
        MD4_STEP0(MD4_H, c,d,a,b,     H_w7c02, S22);
        MD4_STEP0(MD4_H, b,c,d,a,     H_wfc02, S23);

        // Accumulate checksum (like hashcat's bitmap check — prevents dead-code elimination)
        acc ^= uint4(a + MD4M_A, d + MD4M_D, c + MD4M_C, b + MD4M_B);
    }

    // Single write per thread (like hashcat writing only matches)
    digests[gid] = acc;
}

// ============================================================================
// Vec:2 kernel — processes 2 candidates per inner loop iteration
// Uses uint2 vectors for a,b,c,d state and w0
// ============================================================================
kernel void ntlm_bench_v2(
    device const uint*   base_words   [[buffer(0)]],   // [num_threads * 16]
    device const uint2*  words_buf_r  [[buffer(1)]],   // [IL_CNT/2] — packed pairs
    device       uint4*  digests      [[buffer(2)]],   // [num_threads * IL_CNT]
    constant     uint&   il_cnt       [[buffer(3)]],   // inner loop count (must be even)
    uint                 gid          [[thread_position_in_grid]])
{
    // Load base password words (scalar — same for both Vec lanes)
    uint w1  = base_words[gid * 16 +  1];
    uint w2  = base_words[gid * 16 +  2];
    uint w3  = base_words[gid * 16 +  3];
    uint w4  = base_words[gid * 16 +  4];
    uint w5  = base_words[gid * 16 +  5];
    uint w6  = base_words[gid * 16 +  6];
    uint w7  = base_words[gid * 16 +  7];
    uint w8  = base_words[gid * 16 +  8];
    uint w9  = base_words[gid * 16 +  9];
    uint wa  = base_words[gid * 16 + 10];
    uint wb  = base_words[gid * 16 + 11];
    uint wc  = base_words[gid * 16 + 12];
    uint wd  = base_words[gid * 16 + 13];
    uint we  = base_words[gid * 16 + 14];
    uint wf  = base_words[gid * 16 + 15];
    uint w0l = base_words[gid * 16 +  0];

    // Precompute constants (scalar)
    const uint F_w0c00 = MD4C00;     const uint F_w1c00 = w1+MD4C00;
    const uint F_w2c00 = w2+MD4C00;  const uint F_w3c00 = w3+MD4C00;
    const uint F_w4c00 = w4+MD4C00;  const uint F_w5c00 = w5+MD4C00;
    const uint F_w6c00 = w6+MD4C00;  const uint F_w7c00 = w7+MD4C00;
    const uint F_w8c00 = w8+MD4C00;  const uint F_w9c00 = w9+MD4C00;
    const uint F_wac00 = wa+MD4C00;  const uint F_wbc00 = wb+MD4C00;
    const uint F_wcc00 = wc+MD4C00;  const uint F_wdc00 = wd+MD4C00;
    const uint F_wec00 = we+MD4C00;  const uint F_wfc00 = wf+MD4C00;

    const uint G_w0c01 = MD4C01;     const uint G_w4c01 = w4+MD4C01;
    const uint G_w8c01 = w8+MD4C01;  const uint G_wcc01 = wc+MD4C01;
    const uint G_w1c01 = w1+MD4C01;  const uint G_w5c01 = w5+MD4C01;
    const uint G_w9c01 = w9+MD4C01;  const uint G_wdc01 = wd+MD4C01;
    const uint G_w2c01 = w2+MD4C01;  const uint G_w6c01 = w6+MD4C01;
    const uint G_wac01 = wa+MD4C01;  const uint G_wec01 = we+MD4C01;
    const uint G_w3c01 = w3+MD4C01;  const uint G_w7c01 = w7+MD4C01;
    const uint G_wbc01 = wb+MD4C01;  const uint G_wfc01 = wf+MD4C01;

    const uint H_w0c02 = MD4C02;     const uint H_w8c02 = w8+MD4C02;
    const uint H_w4c02 = w4+MD4C02;  const uint H_wcc02 = wc+MD4C02;
    const uint H_w2c02 = w2+MD4C02;  const uint H_wac02 = wa+MD4C02;
    const uint H_w6c02 = w6+MD4C02;  const uint H_wec02 = we+MD4C02;
    const uint H_w1c02 = w1+MD4C02;  const uint H_w9c02 = w9+MD4C02;
    const uint H_w5c02 = w5+MD4C02;  const uint H_wdc02 = wd+MD4C02;
    const uint H_w3c02 = w3+MD4C02;  const uint H_wbc02 = wb+MD4C02;
    const uint H_w7c02 = w7+MD4C02;  const uint H_wfc02 = wf+MD4C02;

    // Inner loop — step by 2 (Vec:2)
    uint4 acc = uint4(0);
    uint il_half = il_cnt / 2u;
    for (uint il_pos = 0; il_pos < il_half; il_pos++) {
        const uint2 w0r = words_buf_r[il_pos];
        const uint2 w0  = uint2(w0l | w0r.x, w0l | w0r.y);

        uint2 a = uint2(MD4M_A); uint2 b = uint2(MD4M_B);
        uint2 c = uint2(MD4M_C); uint2 d = uint2(MD4M_D);

        // F round — w0 varies, rest precomputed
        a = a + uint2(F_w0c00) + w0 + uint2(MD4_F(b.x,c.x,d.x), MD4_F(b.y,c.y,d.y)); a = uint2(rotate(a.x,S00), rotate(a.y,S00));
        d = d + uint2(F_w1c00) + uint2(MD4_F(a.x,b.x,c.x), MD4_F(a.y,b.y,c.y)); d = uint2(rotate(d.x,S01), rotate(d.y,S01));
        c = c + uint2(F_w2c00) + uint2(MD4_F(d.x,a.x,b.x), MD4_F(d.y,a.y,b.y)); c = uint2(rotate(c.x,S02), rotate(c.y,S02));
        b = b + uint2(F_w3c00) + uint2(MD4_F(c.x,d.x,a.x), MD4_F(c.y,d.y,a.y)); b = uint2(rotate(b.x,S03), rotate(b.y,S03));
        a = a + uint2(F_w4c00) + uint2(MD4_F(b.x,c.x,d.x), MD4_F(b.y,c.y,d.y)); a = uint2(rotate(a.x,S00), rotate(a.y,S00));
        d = d + uint2(F_w5c00) + uint2(MD4_F(a.x,b.x,c.x), MD4_F(a.y,b.y,c.y)); d = uint2(rotate(d.x,S01), rotate(d.y,S01));
        c = c + uint2(F_w6c00) + uint2(MD4_F(d.x,a.x,b.x), MD4_F(d.y,a.y,b.y)); c = uint2(rotate(c.x,S02), rotate(c.y,S02));
        b = b + uint2(F_w7c00) + uint2(MD4_F(c.x,d.x,a.x), MD4_F(c.y,d.y,a.y)); b = uint2(rotate(b.x,S03), rotate(b.y,S03));
        a = a + uint2(F_w8c00) + uint2(MD4_F(b.x,c.x,d.x), MD4_F(b.y,c.y,d.y)); a = uint2(rotate(a.x,S00), rotate(a.y,S00));
        d = d + uint2(F_w9c00) + uint2(MD4_F(a.x,b.x,c.x), MD4_F(a.y,b.y,c.y)); d = uint2(rotate(d.x,S01), rotate(d.y,S01));
        c = c + uint2(F_wac00) + uint2(MD4_F(d.x,a.x,b.x), MD4_F(d.y,a.y,b.y)); c = uint2(rotate(c.x,S02), rotate(c.y,S02));
        b = b + uint2(F_wbc00) + uint2(MD4_F(c.x,d.x,a.x), MD4_F(c.y,d.y,a.y)); b = uint2(rotate(b.x,S03), rotate(b.y,S03));
        a = a + uint2(F_wcc00) + uint2(MD4_F(b.x,c.x,d.x), MD4_F(b.y,c.y,d.y)); a = uint2(rotate(a.x,S00), rotate(a.y,S00));
        d = d + uint2(F_wdc00) + uint2(MD4_F(a.x,b.x,c.x), MD4_F(a.y,b.y,c.y)); d = uint2(rotate(d.x,S01), rotate(d.y,S01));
        c = c + uint2(F_wec00) + uint2(MD4_F(d.x,a.x,b.x), MD4_F(d.y,a.y,b.y)); c = uint2(rotate(c.x,S02), rotate(c.y,S02));
        b = b + uint2(F_wfc00) + uint2(MD4_F(c.x,d.x,a.x), MD4_F(c.y,d.y,a.y)); b = uint2(rotate(b.x,S03), rotate(b.y,S03));

        // G round
        a = a + uint2(G_w0c01) + w0 + uint2(MD4_G(b.x,c.x,d.x), MD4_G(b.y,c.y,d.y)); a = uint2(rotate(a.x,S10), rotate(a.y,S10));
        d = d + uint2(G_w4c01) + uint2(MD4_G(a.x,b.x,c.x), MD4_G(a.y,b.y,c.y)); d = uint2(rotate(d.x,S11), rotate(d.y,S11));
        c = c + uint2(G_w8c01) + uint2(MD4_G(d.x,a.x,b.x), MD4_G(d.y,a.y,b.y)); c = uint2(rotate(c.x,S12), rotate(c.y,S12));
        b = b + uint2(G_wcc01) + uint2(MD4_G(c.x,d.x,a.x), MD4_G(c.y,d.y,a.y)); b = uint2(rotate(b.x,S13), rotate(b.y,S13));
        a = a + uint2(G_w1c01) + uint2(MD4_G(b.x,c.x,d.x), MD4_G(b.y,c.y,d.y)); a = uint2(rotate(a.x,S10), rotate(a.y,S10));
        d = d + uint2(G_w5c01) + uint2(MD4_G(a.x,b.x,c.x), MD4_G(a.y,b.y,c.y)); d = uint2(rotate(d.x,S11), rotate(d.y,S11));
        c = c + uint2(G_w9c01) + uint2(MD4_G(d.x,a.x,b.x), MD4_G(d.y,a.y,b.y)); c = uint2(rotate(c.x,S12), rotate(c.y,S12));
        b = b + uint2(G_wdc01) + uint2(MD4_G(c.x,d.x,a.x), MD4_G(c.y,d.y,a.y)); b = uint2(rotate(b.x,S13), rotate(b.y,S13));
        a = a + uint2(G_w2c01) + uint2(MD4_G(b.x,c.x,d.x), MD4_G(b.y,c.y,d.y)); a = uint2(rotate(a.x,S10), rotate(a.y,S10));
        d = d + uint2(G_w6c01) + uint2(MD4_G(a.x,b.x,c.x), MD4_G(a.y,b.y,c.y)); d = uint2(rotate(d.x,S11), rotate(d.y,S11));
        c = c + uint2(G_wac01) + uint2(MD4_G(d.x,a.x,b.x), MD4_G(d.y,a.y,b.y)); c = uint2(rotate(c.x,S12), rotate(c.y,S12));
        b = b + uint2(G_wec01) + uint2(MD4_G(c.x,d.x,a.x), MD4_G(c.y,d.y,a.y)); b = uint2(rotate(b.x,S13), rotate(b.y,S13));
        a = a + uint2(G_w3c01) + uint2(MD4_G(b.x,c.x,d.x), MD4_G(b.y,c.y,d.y)); a = uint2(rotate(a.x,S10), rotate(a.y,S10));
        d = d + uint2(G_w7c01) + uint2(MD4_G(a.x,b.x,c.x), MD4_G(a.y,b.y,c.y)); d = uint2(rotate(d.x,S11), rotate(d.y,S11));
        c = c + uint2(G_wbc01) + uint2(MD4_G(d.x,a.x,b.x), MD4_G(d.y,a.y,b.y)); c = uint2(rotate(c.x,S12), rotate(c.y,S12));
        b = b + uint2(G_wfc01) + uint2(MD4_G(c.x,d.x,a.x), MD4_G(c.y,d.y,a.y)); b = uint2(rotate(b.x,S13), rotate(b.y,S13));

        // H round
        a = a + uint2(H_w0c02) + w0 + uint2(MD4_H(b.x,c.x,d.x), MD4_H(b.y,c.y,d.y)); a = uint2(rotate(a.x,S20), rotate(a.y,S20));
        d = d + uint2(H_w8c02) + uint2(MD4_H(a.x,b.x,c.x), MD4_H(a.y,b.y,c.y)); d = uint2(rotate(d.x,S21), rotate(d.y,S21));
        c = c + uint2(H_w4c02) + uint2(MD4_H(d.x,a.x,b.x), MD4_H(d.y,a.y,b.y)); c = uint2(rotate(c.x,S22), rotate(c.y,S22));
        b = b + uint2(H_wcc02) + uint2(MD4_H(c.x,d.x,a.x), MD4_H(c.y,d.y,a.y)); b = uint2(rotate(b.x,S23), rotate(b.y,S23));
        a = a + uint2(H_w2c02) + uint2(MD4_H(b.x,c.x,d.x), MD4_H(b.y,c.y,d.y)); a = uint2(rotate(a.x,S20), rotate(a.y,S20));
        d = d + uint2(H_wac02) + uint2(MD4_H(a.x,b.x,c.x), MD4_H(a.y,b.y,c.y)); d = uint2(rotate(d.x,S21), rotate(d.y,S21));
        c = c + uint2(H_w6c02) + uint2(MD4_H(d.x,a.x,b.x), MD4_H(d.y,a.y,b.y)); c = uint2(rotate(c.x,S22), rotate(c.y,S22));
        b = b + uint2(H_wec02) + uint2(MD4_H(c.x,d.x,a.x), MD4_H(c.y,d.y,a.y)); b = uint2(rotate(b.x,S23), rotate(b.y,S23));
        a = a + uint2(H_w1c02) + uint2(MD4_H(b.x,c.x,d.x), MD4_H(b.y,c.y,d.y)); a = uint2(rotate(a.x,S20), rotate(a.y,S20));
        d = d + uint2(H_w9c02) + uint2(MD4_H(a.x,b.x,c.x), MD4_H(a.y,b.y,c.y)); d = uint2(rotate(d.x,S21), rotate(d.y,S21));
        c = c + uint2(H_w5c02) + uint2(MD4_H(d.x,a.x,b.x), MD4_H(d.y,a.y,b.y)); c = uint2(rotate(c.x,S22), rotate(c.y,S22));
        b = b + uint2(H_wdc02) + uint2(MD4_H(c.x,d.x,a.x), MD4_H(c.y,d.y,a.y)); b = uint2(rotate(b.x,S23), rotate(b.y,S23));
        a = a + uint2(H_w3c02) + uint2(MD4_H(b.x,c.x,d.x), MD4_H(b.y,c.y,d.y)); a = uint2(rotate(a.x,S20), rotate(a.y,S20));
        d = d + uint2(H_wbc02) + uint2(MD4_H(a.x,b.x,c.x), MD4_H(a.y,b.y,c.y)); d = uint2(rotate(d.x,S21), rotate(d.y,S21));
        c = c + uint2(H_w7c02) + uint2(MD4_H(d.x,a.x,b.x), MD4_H(d.y,a.y,b.y)); c = uint2(rotate(c.x,S22), rotate(c.y,S22));
        b = b + uint2(H_wfc02) + uint2(MD4_H(c.x,d.x,a.x), MD4_H(c.y,d.y,a.y)); b = uint2(rotate(b.x,S23), rotate(b.y,S23));

        // Accumulate (prevents dead-code elimination, like hashcat's bitmap check)
        acc ^= uint4(a.x + MD4M_A + a.y + MD4M_A,
                     d.x + MD4M_D + d.y + MD4M_D,
                     c.x + MD4M_C + c.y + MD4M_C,
                     b.x + MD4M_B + b.y + MD4M_B);
    }

    digests[gid] = acc;
}
