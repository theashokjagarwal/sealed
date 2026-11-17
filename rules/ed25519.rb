# frozen_string_literal: true
# Pure Ruby implementation of Ed25519 (RFC 8032)
# Zero external dependencies. Self-contained cryptographic signature validation.

require 'digest'

module Ed25519
  P = 2**255 - 19
  L = 2**252 + 27742317777372353535851937790883648493
  D = (-121665 * 121666.pow(P - 2, P)) % P
  I = 2.pow((P - 1) / 4, P)

  def self.inv(x)
    x.pow(P - 2, P)
  end

  def self.xrecover(y)
    xx = (y * y - 1) * inv(D * y * y + 1)
    x = xx.pow((P + 3) / 8, P)
    x = (x * I) % P if (x * x - xx) % P != 0
    x = P - x if x.odd?
    x
  end

  By = 4 * inv(5) % P
  Bx = xrecover(By)
  B = [Bx % P, By % P].freeze

  def self.edwards_add(p1, p2)
    x1, y1 = p1
    x2, y2 = p2
    x3 = (x1 * y2 + x2 * y1) * inv(1 + D * x1 * x2 * y1 * y2) % P
    y3 = (y1 * y2 + x1 * x2) * inv(1 - D * x1 * x2 * y1 * y2) % P
    [x3, y3]
  end

  def self.scalarmult(pt, e)
    return [0, 1] if e == 0
    q = scalarmult(pt, e / 2)
    q = edwards_add(q, q)
    q = edwards_add(q, pt) if e.odd?
    q
  end

  def self.encode_int(y)
    (0..31).map { |i| (y >> (8 * i)) & 0xff }.pack('C*')
  end

  def self.decode_int(bytes)
    bytes.bytes.each_with_index.inject(0) { |sum, (b, i)| sum + (b << (8 * i)) }
  end

  def self.encodepoint(pt)
    x, y = pt
    bits = (0..31).map { |i| (y >> (8 * i)) & 0xff }
    bits[31] |= 0x80 if (x & 1) == 1
    bits.pack('C*')
  end

  def self.decodepoint(bytes)
    arr = bytes.bytes
    clamp = arr[31] & 0x7f
    y = (arr[0..30] + [clamp]).each_with_index.inject(0) { |sum, (b, i)| sum + (b << (8 * i)) }
    x = xrecover(y)
    x = P - x if (x & 1) != (arr[31] >> 7)
    [x, y]
  end

  def self.public_key(secret_key)
    h = Digest::SHA512.digest(secret_key)
    a = decode_int(h[0, 32])
    a &= (1 << 254) - 8
    a |= (1 << 254)
    encodepoint(scalarmult(B, a))
  end

  def self.sign(secret_key, message)
    message_b = message.b
    pub = public_key(secret_key)
    h = Digest::SHA512.digest(secret_key)
    a = decode_int(h[0, 32])
    a &= (1 << 254) - 8
    a |= (1 << 254)
    prefix = h[32, 32]

    r = decode_int(Digest::SHA512.digest(prefix + message_b)) % L
    r_pt = encodepoint(scalarmult(B, r))

    k = decode_int(Digest::SHA512.digest(r_pt + pub + message_b)) % L
    s = (r + k * a) % L
    r_pt + encode_int(s)
  end

  def self.verify(pub_bytes, message, sig)
    message_b = message.b
    return false if sig.bytesize != 64 || pub_bytes.bytesize != 32
    r_bytes = sig[0, 32]
    s_bytes = sig[32, 32]
    s = decode_int(s_bytes)
    return false if s >= L

    a_pt = decodepoint(pub_bytes)
    r_pt = decodepoint(r_bytes)

    k = decode_int(Digest::SHA512.digest(r_bytes + pub_bytes + message_b)) % L

    sb = scalarmult(B, s)
    ra = edwards_add(r_pt, scalarmult(a_pt, k))
    encodepoint(sb) == encodepoint(ra)
  rescue StandardError
    false
  end
end
