import logging

from sage.all import ZZ
from sage.all import Zmod

from shared.crt import fast_crt


def _polynomial_hgcd(ring, a0, a1):
    assert a1.degree() < a0.degree()

    if a1.degree() <= a0.degree() / 2:
        return 1, 0, 0, 1

    m = a0.degree() // 2
    b0 = ring(a0.list()[m:])
    b1 = ring(a1.list()[m:])
    R00, R01, R10, R11 = _polynomial_hgcd(ring, b0, b1)
    d = R00 * a0 + R01 * a1
    e = R10 * a0 + R11 * a1
    if e.degree() < m:
        return R00, R01, R10, R11

    q, f = d.quo_rem(e)
    g0 = ring(e.list()[m // 2:])
    g1 = ring(f.list()[m // 2:])
    S00, S01, S10, S11 = _polynomial_hgcd(ring, g0, g1)
    return S01 * R00 + (S00 - q * S01) * R10, S01 * R01 + (S00 - q * S01) * R11, S11 * R00 + (S10 - q * S11) * R10, S11 * R01 + (S10 - q * S11) * R11


def fast_polynomial_gcd(a0, a1):
    """
    Uses a divide-and-conquer algorithm (HGCD) to compute the polynomial gcd.
    More information: Aho A. et al., "The Design and Analysis of Computer Algorithms" (Section 8.9)
    :param a0: the first polynomial
    :param a1: the second polynomial
    :return: the polynomial gcd
    """
    # TODO: implement extended variant of half GCD?
    assert a0.parent() == a1.parent()

    if a0.degree() == a1.degree():
        if a1 == 0:
            return a0
        a0, a1 = a1, a0 % a1
    elif a0.degree() < a1.degree():
        a0, a1 = a1, a0

    assert a0.degree() > a1.degree()
    ring = a0.parent()

    # Optimize recursive tail call.
    while True:
        logging.debug(f"deg(a0) = {a0.degree()}, deg(a1) = {a1.degree()}")
        _, r = a0.quo_rem(a1)
        if r == 0:
            return a1.monic()

        R00, R01, R10, R11 = _polynomial_hgcd(ring, a0, a1)
        b0 = R00 * a0 + R01 * a1
        b1 = R10 * a0 + R11 * a1
        if b1 == 0:
            return b0.monic()

        _, r = b0.quo_rem(b1)
        if r == 0:
            return b1.monic()

        a0 = b1
        a1 = r


def polynomial_gcd_crt(a, b, factors):
    """
    Uses the Chinese Remainder Theorem to compute the polynomial gcd modulo a composite number.
    :param a: the first polynomial
    :param b: the second polynomial
    :param factors: the factors of m (tuples of primes and exponents)
    :return: the polynomial gcd modulo m
    """
    assert a.base_ring() == b.base_ring() == ZZ

    gs = []
    ps = []
    for p, _ in factors:
        zmodp = Zmod(p)
        gs.append(fast_polynomial_gcd(a.change_ring(zmodp), b.change_ring(zmodp)).change_ring(ZZ))
        ps.append(p)

    g, _ = fast_crt(gs, ps)
    return g


def polynomial_xgcd(a, b):
    """
    Computes the extended GCD of two polynomials using Euclid's algorithm.
    :param a: the first polynomial
    :param b: the second polynomial
    :return: a tuple containing r, s, and t
    """
    assert a.base_ring() == b.base_ring()

    r_prev, r = a, b
    s_prev, s = 1, 0
    t_prev, t = 0, 1

    while r:
        try:
            q = r_prev // r
            r_prev, r = r, r_prev - q * r
            s_prev, s = s, s_prev - q * s
            t_prev, t = t, t_prev - q * t
        except RuntimeError:
            raise ArithmeticError("r is not invertible", r)

    return r_prev, s_prev, t_prev


def polynomial_inverse(p, m):
    """
    Computes the inverse of a polynomial modulo a polynomial using the extended GCD.
    :param p: the polynomial
    :param m: the polynomial modulus
    :return: the inverse of p modulo m
    """
    g, s, t = polynomial_xgcd(p, m)
    return s * g.lc() ** -1


def max_norm(p):
    """
    Computes the max norm (infinity norm) of a polynomial.
    :param p: the polynomial
    :return: a tuple containing the monomial degrees of the largest coefficient and the coefficient
    """
    max_degs = None
    max_coeff = 0
    for degs, coeff in p.dict().items():
        if abs(coeff) > max_coeff:
            max_degs = degs
            max_coeff = abs(coeff)

    return max_degs, max_coeff
