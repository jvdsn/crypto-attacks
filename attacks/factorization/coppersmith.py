import logging
import os
import sys
from math import ceil
from math import log
from math import pi
from math import sqrt

from sage.all import ZZ
from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import coron_direct
from shared.small_roots import herrmann_may_multivariate
from shared.small_roots import howgrave_graham


def factorize_p(N, partial_p, beta=0.5, epsilon=0.125, m=None, t=None):
    """
    Recover the prime factors from a modulus using Coppersmith's method and bits of one prime factor p are known.
    More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods" (Section 3.2)
    More information: Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)
    :param N: the modulus
    :param partial_p: the partial prime factor p (PartialInteger)
    :param beta: the parameter beta (default: 0.5)
    :param epsilon: the parameter epsilon (default: 0.125)
    :param m: the number of normal shifts to use (default: automatically computed using beta and epsilon)
    :param t: the number of additional shifts to use (default: automatically computed using beta and epsilon)
    :return: a tuple containing the prime factors, or None if the factors could not be found
    """
    n = partial_p.unknowns
    assert n > 0
    if n == 1:
        m = ceil(max(beta ** 2 / epsilon, 7 * beta)) if m is None else m
        t = int((1 / beta - 1) * m) if t is None else t
        small_roots = howgrave_graham.modular_univariate
    elif n == 2:
        m = ceil((3 * beta * (1 + sqrt(1 - beta))) / epsilon) if m is None else m
        t = int((1 - sqrt(1 - beta)) * m) if t is None else t
        small_roots = herrmann_may_multivariate.modular_multivariate
    else:
        m = ceil((n * (1 / pi * (1 - beta) ** (-0.278465) - beta * log(1 - beta))) / epsilon) if m is None else m
        t = int((1 - (1 - beta) ** (1 / n)) * m) if t is None else t
        small_roots = herrmann_may_multivariate.modular_multivariate

    x = Zmod(N)[tuple(f"x{i}" for i in range(n))].gens()
    f = partial_p.sub(x)
    X = partial_p.get_unknown_bounds()
    logging.info(f"Trying {m = }, {t = }...")
    for roots in small_roots(f, N, m, t, X):
        p = partial_p.sub(roots)
        if 1 < p < N and N % p == 0:
            return p, N // p

    return None


def factorize_pq(N, partial_p, partial_q, k=None):
    """
    Recover the prime factors from a modulus using Coppersmith's method and bits of both prime factors p and q are known.
    :param N: the modulus
    :param partial_p: the partial prime factor p (PartialInteger)
    :param partial_q: the partial prime factor q (PartialInteger)
    :param k: the number of shifts to use for Coron's method, must be set if the total number of unknown components is two (default: None)
    :return: a tuple containing the prime factors, or None if the factors could not be found
    """
    np = partial_p.unknowns
    nq = partial_q.unknowns
    assert np > 0 and nq > 0

    x = ZZ[tuple(f"x{i}" for i in range(np + nq))].gens()
    f = partial_p.sub(x[:np]) * partial_q.sub(x[np:]) - N
    Xp = partial_p.get_unknown_bounds()
    Xq = partial_q.get_unknown_bounds()

    if np == 1 and nq == 1:
        assert k is not None, "k must be set if the total number of unknown components is two."
        logging.info(f"Trying {k = }...")
        for x0, x1 in coron_direct.integer_bivariate(f, k, Xp[0], Xq[0]):
            p = partial_p.sub([x0])
            q = partial_q.sub([x1])
            if p * q == N:
                return p, q
    else:
        # TODO: Jochemsz-May multivariate integer roots?
        # Or "Factoring RSA Modulus with Known Bits from Both p and q: A Lattice Method"?
        pass

    return None
