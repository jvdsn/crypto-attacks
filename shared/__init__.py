import logging
from math import gcd
from math import isqrt


def int_to_bits_le(i, count):
    """
    Converts an integer to bits, little endian.
    :param i: the integer
    :param count: the number of bits
    :return: the bits
    """
    bits = []
    for _ in range(count):
        bits.append(i & 1)
        i >>= 1

    return bits


def bits_to_int_le(bits, count):
    """
    Converts bits to an integer, little endian
    :param bits: the bits
    :param count: the number of bits
    :return: the integer
    """
    i = 0
    for k in range(count):
        i |= (bits[k] & 1) << k

    return i


def floor_div(a, b):
    """
    Returns floor(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: floor(a / b)
    """
    return a // b


def ceil_div(a, b):
    """
    Returns ceil(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: ceil(a / b)
    """
    return a // b + (a % b > 0)


def is_square(x):
    """
    Returns the square root of x if x is a perfect square, or None otherwise.
    :param x: x
    :return: the square root of x or None
    """
    y = isqrt(x)
    return y if y ** 2 == x else None


def symmetric_mod(x, m):
    """
    Computes the symmetric modular reduction.
    :param x: the number to reduce
    :param m: the modulus
    :return: x reduced in the interval [-m/2, m/2]
    """
    return int((x + m + m // 2) % m) - int(m // 2)


def solve_congruence(a, b, m):
    """
    Solves a congruence of the form ax = b mod m.
    :param a: the parameter a
    :param b: the parameter b
    :param m: the modulus m
    :return: a generator generating solutions for x
    """
    g = gcd(a, m)
    a //= g
    b //= g
    n = m // g
    for i in range(g):
        yield (pow(a, -1, n) * b + i * n) % m


def divisors(factors):
    """
    Computes all divisors from a list of factors
    :param factors: the factors (tuples of primes and exponents)
    :return: a generator generating divisors
    """
    divisors = [1]
    yield 1
    for p, e in factors:
        new = []
        for d in divisors:
            for k in range(1, e + 1):
                d_ = p ** k * d
                new.append(d_)
                yield int(d_)

        divisors += new


def make_square_free(x, factors):
    """
    For any integer x, removes all square factors.
    :param x: the value x
    :param factors: the factors of x
    :return: a square-free integer y, corresponding to x with all square factors removed
    """
    for p, e in factors:
        while e > 0 and e % 2 == 0:
            e -= 2
            x //= p
            x //= p
    return int(x)


def roots_of_unity(ring, l, r):
    """
    Generates r-th roots of unity in a ring, with r | l.
    :param ring: the ring, with order n
    :param l: the Carmichael lambda of n
    :param r: r
    :return: a generator generating the roots of unity
    """
    assert l % r == 0, "r should divide l"

    x = ring(2)
    while (g := x ** (l // r)) == 1:
        x += 1

    for i in range(r):
        yield int(g ** i)


def rth_roots(Fq, delta, r):
    """
    Uses the Adleman-Manders-Miller algorithm to extract r-th roots in Fq, with r | q - 1.
    More information: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited" (Table 4)
    :param Fq: the field Fq
    :param delta: the r-th residue delta
    :param r: the r
    :return: a generator generating the rth roots
    """
    delta = Fq(delta)
    q = Fq.order()
    assert (q - 1) % r == 0, "r should divide q - 1"

    p = Fq(1)
    while p ** ((q - 1) // r) == 1:
        p = Fq.random_element()

    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s //= r

    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alpha = (k * s + 1) // r

    a = p ** (pow(r, t - 1, q - 1) * s)
    b = delta ** (r * alpha - 1)
    c = p ** s
    h = 1
    for i in range(1, t):
        d = b ** pow(r, t - 1 - i, q - 1)
        logging.debug(f"Computing the discrete logarithm for {i = }, this may take a long time...")
        j = 0 if d == 1 else -d.log(a)
        b *= (c ** r) ** j
        h *= c ** j
        c **= r

    root = int(delta ** alpha * h)
    for primitive_root in roots_of_unity(Fq, q - 1, r):
        yield root * primitive_root % q


def modinv_range(n, p):
    """
    Computes the modular inverses of the numbers in the range (1, n] (exclusive), mod p.
    More information: grhkm, "[Tutorial] Calculate modulo inverses efficiently!" (Codeforces)
    :param n: the n
    :param p: the modulus
    :return: a generator generating the modular inverses of 1, 2... n - 1 mod p
    """
    inv = [0] * n
    inv[1] = 1
    yield inv[1]
    for i in range(2, n):
        inv[i] = (p - p // i) * inv[p % i] % p
        yield inv[i]


def modinv(a, p):
    """
    Computes the modular inverses a list of numbers mod p.
    More information: grhkm, "[Tutorial] Calculate modulo inverses efficiently!" (Codeforces)
    :param a: the list of numbers
    :param p: the modulus
    :return: a generator generating the modular inverses of a1, a2... mod p
    """
    n = len(a)
    pre = [0] * n
    pre[0] = 1
    suf = [0] * n
    suf[n - 1] = 1
    prod = 1
    for i in range(n - 1):
        pre[i + 1] = pre[i] * a[i] % p
        suf[n - i - 2] = suf[n - i - 1] * a[n - i - 1] % p
        prod = prod * a[i] % p

    prod = prod * a[n - 1] % p
    prod = pow(prod, -1, p)
    for i in range(n):
        yield (pre[i] * suf[i] % p) * prod % p
