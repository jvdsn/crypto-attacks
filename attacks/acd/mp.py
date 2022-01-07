import logging
import os
import sys
from itertools import product
from math import gcd

from sage.all import PolynomialRing
from sage.all import ZZ

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import small_roots


def attack(N, a, rho, t=1, k=1, roots_method="groebner"):
    """
    Solves the ACD problem using the multivariate polynomial approach.
    More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 5)
    :param N: N = p * q0
    :param a: the a samples, with ai = p * qi + ri
    :param rho: the number of bits of the r values
    :param t: the t parameter (default: 1)
    :param k: the k parameter (default: 1)
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: the secret integer p and a list containing the r values, or None if p could not be found
    """
    assert len(a) >= 1, "At least one a value is required."
    assert t >= k, "t must be greater than or equal to k."

    R = 2 ** rho

    pr = PolynomialRing(ZZ, [f"X{i}" for i in range(len(a))])
    gens = pr.gens()
    bounds = [R] * len(gens)

    logging.debug("Generating shifts...")
    shifts = set()
    monomials = set()
    for i in product(*[range(t + 1) for _ in gens]):
        if sum(i) <= t:
            l = max(k - sum(i), 0)
            fi = N ** l
            for m in range(len(i)):
                fi *= (gens[m] - a[m]) ** i[m]

            shifts.add(fi)
            monomials.update(fi.monomials())

    B = small_roots.fill_lattice(shifts, monomials, bounds)
    B = small_roots.reduce(B)
    polynomials = small_roots.reconstruct_polynomials(B, None, monomials, bounds, divide_original=False)
    for roots in small_roots.find_roots(polynomials, pr, method=roots_method):
        r = [roots[gen] for gen in gens]
        p = gcd(N, a[0] - r[0])
        if all(-R < ri < R for ri in r):
            return int(p), r
