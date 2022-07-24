import logging

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import hilbert_class_polynomial
from sage.all import is_prime_power


def hilbert_class_polynomial_roots(D, gf):
    """
    Computes the roots of H_D(X) mod q given D and GF(q).
    TODO: implement "Accelerating the CM method" by Sutherland.
    :param D: the CM discriminant (negative)
    :param gf: the finite field GF(q)
    :return: a generator generating the roots (values j)
    """
    assert D < 0 and (D % 4 == 0 or D % 4 == 1)
    H = hilbert_class_polynomial(D)
    pr = gf["x"]
    for j in pr(H).roots(multiplicities=False):
        yield int(j)


def generate_curve(gf, j, k, c=None):
    """
    Generates an Elliptic Curve given GF(q), j, k, and parameter c
    :param gf: the finite field GF(q)
    :param j: the j-invariant
    :param k: j / (j - 1728) if j != 0 and j != 1728, otherwise None
    :param c: an optional parameter c which is used to generate random a and b values (default: random element in Zmod(q))
    :return:
    """
    c_ = c if c is not None else 0
    while c_ == 0:
        c_ = gf.random_element()

    if j == 0:
        return EllipticCurve(gf, [0, c_])
    if j == gf(1728):
        return EllipticCurve(gf, [c_, 0])

    a = 3 * k * c_ ** 2
    b = 2 * k * c_ ** 3
    return EllipticCurve(gf, [a, b])


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
    if gf.characteristic() == 2 or gf.characteristic() == 3:
        return

    jk = []
    for j in hilbert_class_polynomial_roots(D, gf):
        if j == 0 or j == gf(1728):
            yield generate_curve(gf, j, None, c)
            jk.append((j, None))
        else:
            k = gf(j) / (1728 - j)
            yield generate_curve(gf, j, k, c)
            jk.append((j, k))

    while len(jk) > 0:
        for j, k in jk:
            yield generate_curve(gf, j, k, c)
