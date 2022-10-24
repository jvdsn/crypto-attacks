import logging
import os
import sys
from itertools import product
from math import gcd

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
    :param rho: the bit length of the r values
    :param t: the parameter t (default: 1)
    :param k: the parameter k (default: 1)
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: the secret integer p and a list containing the r values, or None if p could not be found
    """
    assert len(a) > 0, "At least one a value is required."
    assert t >= k, "t must be greater than or equal to k."

    R = 2 ** rho

    pr = ZZ[tuple(f"x{i}" for i in range(len(a)))]
    x = pr.gens()
    X = [R] * len(x)

    logging.debug("Generating shifts...")

    shifts = []
    for i in product(*[range(t + 1) for _ in x]):
        if sum(i) <= t:
            l = max(k - sum(i), 0)
            fi = N ** l
            for m in range(len(i)):
                fi *= (x[m] - a[m]) ** i[m]

            shifts.append(fi)

    B, monomials = small_roots.create_lattice(pr, shifts, X)
    B = small_roots.reduce_lattice(B)
    polynomials = small_roots.reconstruct_polynomials(B, None, N ** k, monomials, X)
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        r = [roots[xi] for xi in x]
        if all(-R < ri < R for ri in r):
            return int(gcd(N, a[0] - r[0])), r
