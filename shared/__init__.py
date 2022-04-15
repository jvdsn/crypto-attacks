import logging
from math import gcd


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


def floor(a, b):
    """
    Returns floor(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: floor(a / b)
    """
    return a // b


def ceil(a, b):
    """
    Returns ceil(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: ceil(a / b)
    """
    return a // b + (a % b > 0)


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
    divisors = [1]
    yield 1
    for p, e in factors:
        new = []
        for d in divisors:
            for k in range(1, e + 1):
                d_ = p ** k * d
                new.append(d_)
                yield d_

        divisors += new


def roots_of_unity(r, Fq):
    """
    Generates rth roots of unity in Fq, with r | q - 1.
    :param r: the r
    :param Fq: the field Fq
    :return: a generator generating the roots of unity
    """
    q = Fq.order()
    assert (q - 1) % r == 0, "r should divide q - 1"

    x = Fq(q - 2)
    while x ** ((q - 1) // r) == 1:
        x -= 1

    g = x ** ((q - 1) // r)
    for i in range(r):
        yield int(g ** i)


def rth_roots(delta, r, Fq):
    """
    Uses the Adleman-Manders-Miller algorithm to extract rth roots in Fq, with r | q - 1.
    More information: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited" (Section 5)
    :param delta: the rth residue delta
    :param r: the r
    :param Fq: the field Fq
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
        logging.debug(f"Computing the discrete logarithm for i = {i}, this may take a long time...")
        j = 0 if d == 1 else -d.log(a)
        b *= (c ** r) ** j
        h *= c ** j
        c **= r

    root = int(delta ** alpha * h)
    for primitive_root in roots_of_unity(r, Fq):
        yield root * primitive_root % q
