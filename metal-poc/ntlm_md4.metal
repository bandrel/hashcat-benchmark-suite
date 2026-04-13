// ntlm_md4.metal — Native Metal compute shader for NTLM (MD4) hashing
// Proof-of-concept for benchmarking against hashcat's OpenCL-to-Metal translated path

#include <metal_stdlib>
using namespace metal;

// ---------------------------------------------------------------------------
// MD4 initial values
// ---------------------------------------------------------------------------
constant uint MD4M_A = 0x67452301u;
constant uint MD4M_B = 0xefcdab89u;
constant uint MD4M_C = 0x98badcfeu;
constant uint MD4M_D = 0x10325476u;

// Round constants
constant uint MD4C00 = 0x00000000u;
constant uint MD4C01 = 0x5a827999u;
constant uint MD4C02 = 0x6ed9eba1u;

// Shift amounts — Round 1
constant uint S00 = 3u;
constant uint S01 = 7u;
constant uint S02 = 11u;
constant uint S03 = 19u;

// Shift amounts — Round 2
constant uint S10 = 3u;
constant uint S11 = 5u;
constant uint S12 = 9u;
constant uint S13 = 13u;

// Shift amounts — Round 3
constant uint S20 = 3u;
constant uint S21 = 9u;
constant uint S22 = 11u;
constant uint S23 = 15u;

// ---------------------------------------------------------------------------
// Round functions — two variants toggled by USE_SELECT
// ---------------------------------------------------------------------------
#ifdef USE_SELECT
// Metal's select() on scalar uint is boolean (whole-value), not bitwise.
// Implement bitwise select manually: bsel(a, b, mask) = (mask & b) | (~mask & a)
// This maps to a BFI (bit field insert) instruction on Apple GPU.
inline uint bsel(uint a, uint b, uint mask) { return (mask & b) | (~mask & a); }
inline uint MD4_F(uint x, uint y, uint z) { return bsel(z, y, x); }
inline uint MD4_G(uint x, uint y, uint z) { return bsel(x, y, x ^ z); }
#else
inline uint MD4_F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
inline uint MD4_G(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
#endif

inline uint MD4_H(uint x, uint y, uint z) { return x ^ y ^ z; }

// ---------------------------------------------------------------------------
// MD4 step macro equivalent
// ---------------------------------------------------------------------------
#define MD4_STEP0(f, a, b, c, d, w, K, s) \
    do { \
        (a) = (a) + (K) + f((b), (c), (d)) + (w); \
        (a) = rotate((a), (s)); \
    } while (0)

// ---------------------------------------------------------------------------
// UTF-16LE expansion: expand 2 ASCII bytes packed in low 16 bits of a uint32
// into a uint32 of two UTF-16LE code units.
// Input byte layout (little-endian): [b0, b1, ...]
// Output: [b0, 0x00, b1, 0x00]  i.e.  (b0 & 0xFF) | ((b1 & 0xFF) << 16)
// ---------------------------------------------------------------------------
inline uint make_utf16le(uint v) {
    return (v & 0xFFu) | ((v & 0xFF00u) << 8u);
}

// ---------------------------------------------------------------------------
// Core MD4 transform on 16 uint32 message words, producing 4-word digest.
// ---------------------------------------------------------------------------
inline uint4 md4_transform(uint w0,  uint w1,  uint w2,  uint w3,
                            uint w4,  uint w5,  uint w6,  uint w7,
                            uint w8,  uint w9,  uint wa,  uint wb,
                            uint wc,  uint wd,  uint we,  uint wf) {
    uint a = MD4M_A;
    uint b = MD4M_B;
    uint c = MD4M_C;
    uint d = MD4M_D;

    // Round 1 — F function, words in order w0..wf
    MD4_STEP0(MD4_F, a, b, c, d, w0, MD4C00, S00);
    MD4_STEP0(MD4_F, d, a, b, c, w1, MD4C00, S01);
    MD4_STEP0(MD4_F, c, d, a, b, w2, MD4C00, S02);
    MD4_STEP0(MD4_F, b, c, d, a, w3, MD4C00, S03);
    MD4_STEP0(MD4_F, a, b, c, d, w4, MD4C00, S00);
    MD4_STEP0(MD4_F, d, a, b, c, w5, MD4C00, S01);
    MD4_STEP0(MD4_F, c, d, a, b, w6, MD4C00, S02);
    MD4_STEP0(MD4_F, b, c, d, a, w7, MD4C00, S03);
    MD4_STEP0(MD4_F, a, b, c, d, w8, MD4C00, S00);
    MD4_STEP0(MD4_F, d, a, b, c, w9, MD4C00, S01);
    MD4_STEP0(MD4_F, c, d, a, b, wa, MD4C00, S02);
    MD4_STEP0(MD4_F, b, c, d, a, wb, MD4C00, S03);
    MD4_STEP0(MD4_F, a, b, c, d, wc, MD4C00, S00);
    MD4_STEP0(MD4_F, d, a, b, c, wd, MD4C00, S01);
    MD4_STEP0(MD4_F, c, d, a, b, we, MD4C00, S02);
    MD4_STEP0(MD4_F, b, c, d, a, wf, MD4C00, S03);

    // Round 2 — G function, word access order: 0,4,8,c,1,5,9,d,2,6,a,e,3,7,b,f
    MD4_STEP0(MD4_G, a, b, c, d, w0, MD4C01, S10);
    MD4_STEP0(MD4_G, d, a, b, c, w4, MD4C01, S11);
    MD4_STEP0(MD4_G, c, d, a, b, w8, MD4C01, S12);
    MD4_STEP0(MD4_G, b, c, d, a, wc, MD4C01, S13);
    MD4_STEP0(MD4_G, a, b, c, d, w1, MD4C01, S10);
    MD4_STEP0(MD4_G, d, a, b, c, w5, MD4C01, S11);
    MD4_STEP0(MD4_G, c, d, a, b, w9, MD4C01, S12);
    MD4_STEP0(MD4_G, b, c, d, a, wd, MD4C01, S13);
    MD4_STEP0(MD4_G, a, b, c, d, w2, MD4C01, S10);
    MD4_STEP0(MD4_G, d, a, b, c, w6, MD4C01, S11);
    MD4_STEP0(MD4_G, c, d, a, b, wa, MD4C01, S12);
    MD4_STEP0(MD4_G, b, c, d, a, we, MD4C01, S13);
    MD4_STEP0(MD4_G, a, b, c, d, w3, MD4C01, S10);
    MD4_STEP0(MD4_G, d, a, b, c, w7, MD4C01, S11);
    MD4_STEP0(MD4_G, c, d, a, b, wb, MD4C01, S12);
    MD4_STEP0(MD4_G, b, c, d, a, wf, MD4C01, S13);

    // Round 3 — H function, word access order: 0,8,4,c,2,a,6,e,1,9,5,d,3,b,7,f
    MD4_STEP0(MD4_H, a, b, c, d, w0, MD4C02, S20);
    MD4_STEP0(MD4_H, d, a, b, c, w8, MD4C02, S21);
    MD4_STEP0(MD4_H, c, d, a, b, w4, MD4C02, S22);
    MD4_STEP0(MD4_H, b, c, d, a, wc, MD4C02, S23);
    MD4_STEP0(MD4_H, a, b, c, d, w2, MD4C02, S20);
    MD4_STEP0(MD4_H, d, a, b, c, wa, MD4C02, S21);
    MD4_STEP0(MD4_H, c, d, a, b, w6, MD4C02, S22);
    MD4_STEP0(MD4_H, b, c, d, a, we, MD4C02, S23);
    MD4_STEP0(MD4_H, a, b, c, d, w1, MD4C02, S20);
    MD4_STEP0(MD4_H, d, a, b, c, w9, MD4C02, S21);
    MD4_STEP0(MD4_H, c, d, a, b, w5, MD4C02, S22);
    MD4_STEP0(MD4_H, b, c, d, a, wd, MD4C02, S23);
    MD4_STEP0(MD4_H, a, b, c, d, w3, MD4C02, S20);
    MD4_STEP0(MD4_H, d, a, b, c, wb, MD4C02, S21);
    MD4_STEP0(MD4_H, c, d, a, b, w7, MD4C02, S22);
    MD4_STEP0(MD4_H, b, c, d, a, wf, MD4C02, S23);

    // Add initial values
    a += MD4M_A;
    b += MD4M_B;
    c += MD4M_C;
    d += MD4M_D;

    return uint4(a, b, c, d);
}

// ---------------------------------------------------------------------------
// ntlm_bench kernel
// Input:  candidates — array of uint4 (4 uint32s = up to 16 raw password bytes each)
//         lengths    — password length in bytes for each candidate
// Output: digests    — array of uint4 (MD4 digest a,b,c,d)
// ---------------------------------------------------------------------------
kernel void ntlm_bench(
    device const uint4*  candidates [[buffer(0)]],
    device const uint*   lengths    [[buffer(1)]],
    device       uint4*  digests    [[buffer(2)]],
    uint                 gid        [[thread_position_in_grid]])
{
    uint4 cand = candidates[gid];
    uint  pw_len = lengths[gid];

    // Extract raw bytes from the 4 input uint32s
    uint in0 = cand.x;
    uint in1 = cand.y;
    uint in2 = cand.z;
    uint in3 = cand.w;

    // UTF-16LE expansion: each input uint32 holds 4 bytes → expands to 2 uint32s
    // make_utf16le takes low 16 bits (2 bytes) and expands them
    uint w0 = make_utf16le(in0);                       // bytes 0,1
    uint w1 = make_utf16le(in0 >> 16u);                // bytes 2,3
    uint w2 = make_utf16le(in1);                       // bytes 4,5
    uint w3 = make_utf16le(in1 >> 16u);                // bytes 6,7
    uint w4 = make_utf16le(in2);                       // bytes 8,9
    uint w5 = make_utf16le(in2 >> 16u);                // bytes 10,11
    uint w6 = make_utf16le(in3);                       // bytes 12,13
    uint w7 = make_utf16le(in3 >> 16u);                // bytes 14,15

    // Zero out words beyond the password length
    // Each original byte becomes 2 bytes in UTF-16LE, so each uint32 covers 2 original bytes
    // Word i covers original bytes [2*i, 2*i+1]
    if (pw_len < 15u) w7 = 0u;
    if (pw_len < 13u) w6 = 0u;
    if (pw_len < 11u) w5 = 0u;
    if (pw_len < 9u)  w4 = 0u;
    if (pw_len < 7u)  w3 = 0u;
    if (pw_len < 5u)  w2 = 0u;
    if (pw_len < 3u)  w1 = 0u;
    if (pw_len < 1u)  w0 = 0u;

    // Apply 0x80 padding after the last UTF-16LE character
    // In UTF-16LE, each char is 2 bytes. The password has pw_len characters in UTF-16LE
    // representation = pw_len * 2 bytes. The 0x80 goes at byte offset pw_len * 2.
    // Since we're working in uint32 words of 4 bytes each, the word index = (pw_len * 2) / 4 = pw_len / 2
    // and the byte position within that word = (pw_len * 2) % 4 = (pw_len & 1) * 2
    uint pad_word = pw_len / 2u;
    uint pad_shift = (pw_len & 1u) * 16u;
    uint pad_val = 0x80u << pad_shift;

    // Apply padding to the correct word
    if (pad_word == 0u) w0 |= pad_val;
    else if (pad_word == 1u) w1 |= pad_val;
    else if (pad_word == 2u) w2 |= pad_val;
    else if (pad_word == 3u) w3 |= pad_val;
    else if (pad_word == 4u) w4 |= pad_val;
    else if (pad_word == 5u) w5 |= pad_val;
    else if (pad_word == 6u) w6 |= pad_val;
    else if (pad_word == 7u) w7 |= pad_val;

    // Remaining message words
    uint w8 = (pad_word == 8u) ? pad_val : 0u;
    uint w9 = 0u;
    uint wa = 0u;
    uint wb = 0u;
    uint wc = 0u;
    uint wd = 0u;
    uint we = pw_len * 16u;  // bit length = pw_len * 2 (UTF-16LE bytes) * 8 (bits)
    uint wf = 0u;

    digests[gid] = md4_transform(w0, w1, w2, w3, w4, w5, w6, w7,
                                  w8, w9, wa, wb, wc, wd, we, wf);
}

// ---------------------------------------------------------------------------
// ntlm_verify kernel — same as ntlm_bench but also checks against a target hash
// results[gid] = 1 if match, 0 otherwise
// ---------------------------------------------------------------------------
kernel void ntlm_verify(
    device const uint4*  candidates [[buffer(0)]],
    device const uint*   lengths    [[buffer(1)]],
    device       uint4*  digests    [[buffer(2)]],
    device const uint4*  target     [[buffer(3)]],
    device       uint*   results    [[buffer(4)]],
    uint                 gid        [[thread_position_in_grid]])
{
    uint4 cand = candidates[gid];
    uint  pw_len = lengths[gid];

    uint in0 = cand.x;
    uint in1 = cand.y;
    uint in2 = cand.z;
    uint in3 = cand.w;

    uint w0 = make_utf16le(in0);
    uint w1 = make_utf16le(in0 >> 16u);
    uint w2 = make_utf16le(in1);
    uint w3 = make_utf16le(in1 >> 16u);
    uint w4 = make_utf16le(in2);
    uint w5 = make_utf16le(in2 >> 16u);
    uint w6 = make_utf16le(in3);
    uint w7 = make_utf16le(in3 >> 16u);

    if (pw_len < 15u) w7 = 0u;
    if (pw_len < 13u) w6 = 0u;
    if (pw_len < 11u) w5 = 0u;
    if (pw_len < 9u)  w4 = 0u;
    if (pw_len < 7u)  w3 = 0u;
    if (pw_len < 5u)  w2 = 0u;
    if (pw_len < 3u)  w1 = 0u;
    if (pw_len < 1u)  w0 = 0u;

    uint pad_word = pw_len / 2u;
    uint pad_shift = (pw_len & 1u) * 16u;
    uint pad_val = 0x80u << pad_shift;

    if (pad_word == 0u) w0 |= pad_val;
    else if (pad_word == 1u) w1 |= pad_val;
    else if (pad_word == 2u) w2 |= pad_val;
    else if (pad_word == 3u) w3 |= pad_val;
    else if (pad_word == 4u) w4 |= pad_val;
    else if (pad_word == 5u) w5 |= pad_val;
    else if (pad_word == 6u) w6 |= pad_val;
    else if (pad_word == 7u) w7 |= pad_val;

    uint w8 = (pad_word == 8u) ? pad_val : 0u;
    uint w9 = 0u;
    uint wa = 0u;
    uint wb = 0u;
    uint wc = 0u;
    uint wd = 0u;
    uint we = pw_len * 16u;
    uint wf = 0u;

    uint4 digest = md4_transform(w0, w1, w2, w3, w4, w5, w6, w7,
                                  w8, w9, wa, wb, wc, wd, we, wf);
    digests[gid] = digest;

    uint4 t = target[0];
    results[gid] = (digest.x == t.x && digest.y == t.y &&
                    digest.z == t.z && digest.w == t.w) ? 1u : 0u;
}
