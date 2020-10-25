import logging
from math import log2

from sage.all import PolynomialRing
from sage.all import Zmod
from sage.all import discrete_log
from sage.all import factor

from small_roots.howgrave_graham import modular_univariate


def _prime_power_divisors(n):
    divisors = []
    for p, e in factor(n):
        for i in range(1, e + 1):
            divisors.append(p ** i)

    divisors.sort()
    return divisors


def _compute_max_primorial_(primorial, order):
    for p in _prime_power_divisors(primorial):
        orderp = Zmod(p)(65537).multiplicative_order()
        if order % orderp != 0:
            primorial //= p

    return primorial


def _greedy_find_primorial_(n, primorial):
    order = Zmod(primorial)(65537).multiplicative_order()
    while True:
        best_reward = 0
        best_order = order
        best_primorial_ = primorial
        for p in _prime_power_divisors(order):
            order_ = order // p
            primorial_ = _compute_max_primorial_(primorial, order_)
            r = (log2(order) - log2(order_)) / (log2(primorial) - log2(primorial_))
            if r > best_reward:
                best_reward = r
                best_order = order_
                best_primorial_ = primorial_

        if log2(best_primorial_) < log2(n) / 4:
            return primorial

        order = best_order
        primorial = best_primorial_


def attack(n, primorial, m):
    """
    Recovers the prime factors from a modulus using the ROCA method.
    More information: Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"
    :param n: the modulus
    :param primorial: the primorial used to generate the primes
    :param m: the m parameter for Coppersmith's method
    :return: a tuple containing the prime factors
    """
    logging.debug("Generating primorial_...")
    primorial_ = _greedy_find_primorial_(n, primorial)
    inverse_primorial_ = pow(primorial_, -1, n)
    e = Zmod(primorial_)(65537)
    c = discrete_log(n, e)
    order = e.multiplicative_order()

    logging.debug("Starting exhaustive a search...")
    pr = PolynomialRing(Zmod(n), "x")
    x = pr.gen()
    bound = int(2 * n ** 0.5 // primorial_)
    for a in range(c // 2, (c + order) // 2 + 1):
        f = x + inverse_primorial_ * int(e ** a)
        for root in modular_univariate(f, n, m, m + 1, bound):
            p = root * primorial_ + int(e ** a)
            if n % p == 0:
                return p, n // p
