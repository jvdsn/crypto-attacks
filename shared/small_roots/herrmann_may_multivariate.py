import logging
from math import gcd

from sage.all import ZZ

from shared import small_roots


def _get_shifts(m, x, k, shift, j, sum, shifts):
    if j == len(x):
        shifts.append(shift)
    else:
        for ij in range(m + 1 - k - sum):
            _get_shifts(m, x, k, shift * x[j] ** ij, j + 1, sum + ij, shifts)


def modular_multivariate(f, N, m, t, X, roots_method="groebner"):
    """
    Computes small modular roots of a multivariate polynomial.
    More information: Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)
    :param f: the polynomial
    :param N: the modulus
    :param m: the the parameter m
    :param t: the the parameter t
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

    shifts = []
    for k in range(m + 1):
        _get_shifts(m, x, k, f_ ** k * N ** max(t - k, 0), 1, 0, shifts)

    L, monomials = small_roots.create_lattice(pr, shifts, X)
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, N, monomials, X)
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield tuple(roots[xi] for xi in x)
