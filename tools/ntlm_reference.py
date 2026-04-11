"""NTLM hash reference implementation.

Computes NTLM hashes (MD4 of UTF-16LE encoded password) for use as a
correctness oracle when validating hashcat output.

On Python versions where hashlib supports MD4, we use that. Otherwise
we fall back to a pure-Python MD4 implementation (needed on Python 3.14+
where OpenSSL has removed legacy digests).
"""

import struct


# ---------------------------------------------------------------------------
# Pure-Python MD4 (RFC 1320)
# ---------------------------------------------------------------------------

def _left_rotate(n, b):
    """32-bit left rotate."""
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def _md4(message: bytes) -> bytes:
    """Compute MD4 digest of *message*, returning 16 raw bytes."""
    # Initial hash values
    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    # Pre-processing: add padding
    msg = bytearray(message)
    orig_len_bits = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", orig_len_bits)

    # Process each 512-bit (64-byte) block
    for offset in range(0, len(msg), 64):
        block = msg[offset : offset + 64]
        X = list(struct.unpack("<16I", block))

        a, b, c, d = a0, b0, c0, d0

        # Round 1: F(b, c, d) = (b & c) | (~b & d)
        for i, (k, s) in enumerate([
            (0, 3), (1, 7), (2, 11), (3, 19),
            (4, 3), (5, 7), (6, 11), (7, 19),
            (8, 3), (9, 7), (10, 11), (11, 19),
            (12, 3), (13, 7), (14, 11), (15, 19),
        ]):
            f = (b & c) | ((~b) & d)
            f = (a + f + X[k]) & 0xFFFFFFFF
            a, b, c, d = d, _left_rotate(f, s), b, c

        # Round 2: G(b, c, d) = (b & c) | (b & d) | (c & d)
        for k, s in [
            (0, 3), (4, 5), (8, 9), (12, 13),
            (1, 3), (5, 5), (9, 9), (13, 13),
            (2, 3), (6, 5), (10, 9), (14, 13),
            (3, 3), (7, 5), (11, 9), (15, 13),
        ]:
            g = (b & c) | (b & d) | (c & d)
            g = (a + g + X[k] + 0x5A827999) & 0xFFFFFFFF
            a, b, c, d = d, _left_rotate(g, s), b, c

        # Round 3: H(b, c, d) = b ^ c ^ d
        for k, s in [
            (0, 3), (8, 9), (4, 11), (12, 15),
            (2, 3), (10, 9), (6, 11), (14, 15),
            (1, 3), (9, 9), (5, 11), (13, 15),
            (3, 3), (11, 9), (7, 11), (15, 15),
        ]:
            h = b ^ c ^ d
            h = (a + h + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF
            a, b, c, d = d, _left_rotate(h, s), b, c

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


# ---------------------------------------------------------------------------
# Try hashlib first, fall back to pure-Python
# ---------------------------------------------------------------------------

def _make_ntlm_func():
    """Return the best available ntlm_hash implementation."""
    try:
        import hashlib
        # Try with usedforsecurity=False first (Python 3.9+, OpenSSL 3.x)
        hashlib.new("md4", b"", usedforsecurity=False).hexdigest()

        def _ntlm_hashlib(password: str) -> str:
            return hashlib.new(
                "md4", password.encode("utf-16-le"), usedforsecurity=False
            ).hexdigest()

        return _ntlm_hashlib
    except (ValueError, TypeError):
        pass

    try:
        import hashlib
        hashlib.new("md4", b"").hexdigest()

        def _ntlm_hashlib_legacy(password: str) -> str:
            return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()

        return _ntlm_hashlib_legacy
    except (ValueError, TypeError):
        pass

    # Fall back to pure-Python MD4
    def _ntlm_pure(password: str) -> str:
        return _md4(password.encode("utf-16-le")).hex()

    return _ntlm_pure


ntlm_hash = _make_ntlm_func()
ntlm_hash.__doc__ = (
    "Compute NTLM hash (MD4 of UTF-16LE encoded password). "
    "Returns lowercase 32-char hex string."
)
