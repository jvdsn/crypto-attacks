import logging
from math import log2

from sage.all import Zmod
from sage.all import factor

from small_roots.howgrave_graham import modular_univariate


def _prime_power_divisors(n):
    divisors = []
    for p, e in factor(n):
        for i in range(1, e + 1):
            divisors.append(p ** i)

    divisors.sort()
    return divisors


# Algorithm 2.
def compute_max_M_(M, ord_):
    for p in _prime_power_divisors(M):
        ordp = Zmod(p)(65537).multiplicative_order()
        if ord_ % ordp != 0:
            M //= p

    return M


# Section 2.7.2.
def _greedy_find_M_(n, M):
    ord = Zmod(M)(65537).multiplicative_order()
    while True:
        best_r = 0
        best_ord_ = ord
        best_M_ = M
        for p in _prime_power_divisors(ord):
            ord_ = ord // p
            M_ = compute_max_M_(M, ord_)
            r = (log2(ord) - log2(ord_)) / (log2(M) - log2(M_))
            if r > best_r:
                best_r = r
                best_ord_ = ord_
                best_M_ = M_

        if log2(best_M_) < log2(n) / 4:
            return M

        ord = best_ord_
        M = best_M_


def factorize(n, M, m, t):
    """
    Recovers the prime factors from a modulus using the ROCA method.
    More information: Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"
    :param n: the modulus
    :param M: the primorial used to generate the primes
    :param m: the m parameter for Coppersmith's method
    :param t: the t parameter for Coppersmith's method
    :return: a tuple containing the prime factors
    """
    logging.debug("Generating M'...")
    M_ = _greedy_find_M_(n, M)
    ZmodM_ = Zmod(M_)
    e = ZmodM_(65537)
    c_ = ZmodM_(n).log(e)
    ord_ = e.multiplicative_order()

    x = Zmod(n)["x"].gen()
    X = int(2 * n ** 0.5 // M_)
    logging.debug("Starting exhaustive a' search...")
    for a_ in range(c_ // 2, (c_ + ord_) // 2 + 1):
        f = M_ * x + int(e ** a_)
        for k_ in modular_univariate(f, n, m, t, X):
            p = int(f(k_))
            if n % p == 0:
                return p, n // p
