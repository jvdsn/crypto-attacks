import logging

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import hilbert_class_polynomial
from sage.all import is_prime_power
from sage.all import pari


def hilbert_class_polynomial_roots(D, q):
    """
    Computes the roots of H_D(X) mod q given D and q.
    TODO: implement "Accelerating the CM method" by Sutherland.
    :param D: the CM discriminant (negative)
    :param q: the modulus q
    :return: a generator generating the roots (values j)
    """
    assert D < 0 and (D % 4 == 0 or D % 4 == 1)
    H = hilbert_class_polynomial(D)
    pr = GF(q)["x"]
    for j in pr(H).roots(multiplicities=False):
        yield int(j)


def solve_cm(D, q, c=None):
    """
    Solves a Complex Multiplication equation for a given discriminant D, prime q, and parameter c.
    :param D: the CM discriminant (negative)
    :param q: the prime q
    :param c: an optional parameter c which is used to generate random a and b values (default: random element in Zmod(q))
    :return: a generator generating elliptic curves in Zmod(q) with random a and b values
    """
    assert is_prime_power(q)

    logging.debug(f"Solving CM equation for q = {q} using D = {D} and c = {c}")
    gf = GF(q)
    ks = []
    for j in hilbert_class_polynomial_roots(D, q):
        k = gf(j) / (1728 - j)
        ks.append(k)
        c_ = c if c is not None else gf.random_element()
        a = 3 * k * c_ ** 2
        b = 2 * k * c_ ** 3
        if a > 0 or b > 0:
            yield EllipticCurve(gf, [a, b])

    while True:
        for k in ks:
            c_ = c if c is not None else gf.random_element()
            a = 3 * k * c_ ** 2
            b = 2 * k * c_ ** 3
            if a > 0 or b > 0:
                yield EllipticCurve(gf, [a, b])
