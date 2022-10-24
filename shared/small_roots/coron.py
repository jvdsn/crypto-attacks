import logging
from math import gcd

from sage.all import ZZ

from shared import small_roots
from shared.polynomial import max_norm


def integer_bivariate(p, k, X, Y, roots_method="groebner"):
    """
    Computes small integer roots of a bivariate polynomial.
    More information: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations Revisited"
    Note: integer_bivariate in the coron_direct will probably be more efficient.
    :param p: the polynomial
    :param k: the amount of shifts to use
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    pr = p.parent()
    x, y = pr.gens()
    delta = max(p.degrees())

    _, W = max_norm(p(x * X, y * Y))

    p00 = int(p.constant_coefficient())
    assert p00 != 0
    while gcd(p00, X) != 1:
        X += 1
    while gcd(p00, Y) != 1:
        Y += 1
    while gcd(p00, W) != 1:
        W += 1

    u = W + (1 - W) % abs(p00)
    n = u * (X * Y) ** k
    assert gcd(p00, n) == 1
    q = ((pow(p00, -1, n) * p) % n).change_ring(ZZ)

    logging.debug("Generating shifts...")

    shifts = []
    for i in range(k + delta + 1):
        for j in range(k + delta + 1):
            if i <= k and j <= k:
                shifts.append(x ** i * y ** j * X ** (k - i) * Y ** (k - j) * q)
            else:
                shifts.append(x ** i * y ** j * n)

    L, monomials = small_roots.create_lattice(pr, shifts, [X, Y])
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, p, n, monomials, [X, Y])
    for roots in small_roots.find_roots(pr, [p] + polynomials, method=roots_method):
        yield roots[x], roots[y]
