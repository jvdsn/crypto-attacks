import logging

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import hilbert_class_polynomial
from sage.all import is_prime_power


def elementary_symmetric_function(x, k):
    assert k > 0

    if k > len(x):
        return 0

    e = [0] * k
    for i, xi in enumerate(x):
        ej = e[0]
        e[0] += xi
        ej_1 = ej
        for j in range(1, min(k, i + 1)):
            ej = e[j]
            e[j] += xi * ej_1
            ej_1 = ej

    return e[k - 1]


def hilbert_class_polynomial_roots(D, gf):
    """
    Computes the roots of H_D(X) mod q given D and GF(q).
    TODO: implement "Accelerating the CM method" by Sutherland.
    :param D: the CM discriminant (negative)
    :param gf: the finite field GF(q)
    :return: a generator generating the roots (values j)
    """
    assert D < 0 and (D % 4 == 0 or D % 4 == 1), "D must be negative and a discriminant"
    H = hilbert_class_polynomial(D)
    pr = gf["x"]
    for j in pr(H).roots(multiplicities=False):
        yield j


def generate_curve(gf, k, c=None):
    """
    Generates an Elliptic Curve given GF(q), k, and parameter c
    :param gf: the finite field GF(q)
    :param k: j / (j - 1728)
    :param c: an optional parameter c which is used to generate random a and b values (default: random element in Zmod(q))
    :return:
    """
    c_ = c if c is not None else 0
    while c_ == 0:
        c_ = gf.random_element()

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

    logging.debug(f"Solving CM equation for {q = } using {D = } and {c = }")
    gf = GF(q)
    if gf.characteristic() == 2 or gf.characteristic() == 3:
        return

    ks = []
    for j in hilbert_class_polynomial_roots(D, gf):
        if j != 0 and j != gf(1728):
            k = j / (1728 - j)
            yield generate_curve(gf, k, c)
            ks.append(k)

    while len(ks) > 0:
        for k in ks:
            yield generate_curve(gf, k, c)
