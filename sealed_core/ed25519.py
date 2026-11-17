"""Pure Python implementation of Ed25519 (RFC 8032).

Zero external dependencies. Self-contained cryptographic signature creation
and verification for SEALED compliance rule packs.
"""

import hashlib
from typing import Tuple

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_BX = _xrecover(_BY)
B: Tuple[int, int] = (_BX % P, _BY % P)


def edwards_add(p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    x1x2y1y2 = (D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + x2 * y1) * _inv(1 + x1x2y1y2)) % P
    y3 = ((y1 * y2 + x1 * x2) * _inv(1 - x1x2y1y2)) % P
    return (x3, y3)


def scalarmult(pt: Tuple[int, int], e: int) -> Tuple[int, int]:
    result = (0, 1)
    addend = pt
    while e > 0:
        if e & 1:
            result = edwards_add(result, addend)
        addend = edwards_add(addend, addend)
        e >>= 1
    return result


def encode_int(y: int) -> bytes:
    return y.to_bytes(32, "little")


def decode_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def encodepoint(pt: Tuple[int, int]) -> bytes:
    x, y = pt
    bits = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        bits[31] |= 0x80
    return bytes(bits)


def decodepoint(data: bytes) -> Tuple[int, int]:
    if len(data) != 32:
        raise ValueError("Encoded point must be 32 bytes")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (data[31] >> 7):
        x = P - x
    # Verify point lies on the curve
    if (-x * x + y * y - 1 - D * x * x * y * y) % P != 0:
        raise ValueError("Point is not on Ed25519 curve")
    return (x, y)


def public_key(secret_key: bytes) -> bytes:
    h = hashlib.sha512(secret_key).digest()
    a = decode_int(h[:32])
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encodepoint(scalarmult(B, a))


def sign(secret_key: bytes, message: bytes) -> bytes:
    pub = public_key(secret_key)
    h = hashlib.sha512(secret_key).digest()
    a = decode_int(h[:32])
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:64]

    r = decode_int(hashlib.sha512(prefix + message).digest()) % L
    r_bytes = encodepoint(scalarmult(B, r))

    k = decode_int(hashlib.sha512(r_bytes + pub + message).digest()) % L
    s = (r + k * a) % L
    return r_bytes + encode_int(s)


def verify(pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(pub_bytes) != 32:
        return False
    try:
        r_bytes = signature[:32]
        s_bytes = signature[32:64]
        s = decode_int(s_bytes)
        if s >= L:
            return False

        a_pt = decodepoint(pub_bytes)
        r_pt = decodepoint(r_bytes)

        k = decode_int(hashlib.sha512(r_bytes + pub_bytes + message).digest()) % L

        sb = scalarmult(B, s)
        ra = edwards_add(r_pt, scalarmult(a_pt, k))
        return encodepoint(sb) == encodepoint(ra)
    except Exception:
        return False
