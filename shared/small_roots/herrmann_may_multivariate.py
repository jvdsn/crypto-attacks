import logging
from math import gcd

from sage.all import ZZ

from shared import small_roots


def _get_shifts(m, x, k, shift, j, sum):
    if j == len(x):
        yield shift
    else:
        for ij in range(m + 1 - k - sum):
            yield from _get_shifts(m, x, k, shift * x[j] ** ij, j + 1, sum + ij)


def modular_multivariate(f, N, m, t, X, roots_method="groebner"):
    """
    Computes small modular roots of a multivariate polynomial.
    More information: Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)
    :param f: the polynomial
    :param N: the modulus
    :param m: the the parameter m
    :param m: the the parameter t
    :param X: a list of approximate bounds on the roots for each variable
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples) of the polynomial
    """
    f = f.change_ring(ZZ)
    pr = f.parent()
    x = pr.gens()

    # Sage lm method depends on the term ordering
    l = 1
    for monomial in f.monomials():
        if monomial % l == 0:
            l = monomial

    al = int(f.coefficient(l))
    assert gcd(al, N) == 1
    f_ = (pow(al, -1, N) * f % N).change_ring(ZZ)

    logging.debug("Generating shifts...")

    shifts = set()
    monomials = set()
    for k in range(m + 1):
        for g in _get_shifts(m, x, k, f_ ** k * N ** max(t - k, 0), 1, 0):
            shifts.add(g)
            monomials.update(g.monomials())

    L = small_roots.fill_lattice(shifts, monomials, X)
    L = small_roots.reduce(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, monomials, X)
    for roots in small_roots.find_roots(polynomials, pr, method=roots_method):
        yield tuple(roots[xi] for xi in x)
