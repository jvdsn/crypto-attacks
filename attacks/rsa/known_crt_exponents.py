import logging
import os
import sys
from math import ceil
from math import gcd
from math import log

from sage.all import Zmod
from sage.all import is_prime

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import ceil_div
from shared.small_roots import herrmann_may
from shared.small_roots import howgrave_graham


def _get_possible_primes(e, d):
    logging.debug(f"Looking for possible primes for {e = }, {d = }")
    mul = e * d - 1
    for k in range(3, e):
        if mul % k == 0:
            p = (mul // k) + 1
            if is_prime(p):
                yield p


def attack(e_start, e_end, N=None, dp=None, dq=None, p_bit_length=None, q_bit_length=None):
    """
    Generates possible prime factors for a modulus, if d_p and/or d_q are known.
    More information: Campagna M., Sethi A., "Key Recovery Method for CRT Implementation of RSA"
    :param e_start: the start value of the public exponent (inclusive)
    :param e_end: the end value of the public exponent (exclusive)
    :param N: the modulus, will be used to check the factors if not None (default: None)
    :param dp: the d exponent for p, will be used to generate possible factors for p if not None (default: None)
    :param dq: the d exponent for q, will be used to generate possible factors for q if not None (default: None)
    :param p_bit_length: the bit length of p, will be used to check possible factors for p if not None (default: None)
    :param q_bit_length: the bit length of q, will be used to check possible factors for q if not None (default: None)
    :return: a generator generating tuples containing possible prime factors
    """
    assert not (dp is None and dq is None), "At least one of the CRT private exponents should be known."

    if dp is not None and dq is not None:
        for e in range(e_start, e_end, 2):
            for p in _get_possible_primes(e, dp):
                for q in _get_possible_primes(e, dq):
                    if (N is None or p * q == N) and (p_bit_length is None or p.bit_length() == p_bit_length) and (q_bit_length is None or q.bit_length() == q_bit_length):
                        yield p, q

        return None

    if dp is not None:
        for e in range(e_start, e_end, 2):
            for p in _get_possible_primes(e, dp):
                if p_bit_length is None or p.bit_length() == p_bit_length:
                    if N is None:
                        yield p
                    elif N % p == 0:
                        yield p, N // p

        return None

    if dq is not None:
        for e in range(e_start, e_end, 2):
            for q in _get_possible_primes(e, dq):
                if q_bit_length is None or q.bit_length() == q_bit_length:
                    if N is None:
                        yield q
                    elif N % q == 0:
                        yield q, N // q

        return None


def _factor_msb(N, e, dpM, dp_unknown_lsb, k, m, t):
    logging.info(f"Trying {k = }")
    g = gcd(e, k * N)
    x = Zmod(k * N)["x"].gen()
    f = x + (e * dpM * 2 ** dp_unknown_lsb + k - 1) * pow(e, -1, k // g * N)
    X = 2 ** dp_unknown_lsb
    logging.info(f"Trying {m = }, {t = }...")
    for x0, in howgrave_graham.modular_univariate(f, k * N, m, t, X):
        dp = int(f(x0))
        p = gcd(dp, N)
        if N % p == 0:
            return p, N // p


def _factor_lsb(N, e, dpL, dpL_bit_length, dp_unknown_msb, k, m, t):
    logging.info(f"Trying {k = }")
    g = gcd(2 ** dpL_bit_length * e, k * N)
    x = Zmod(k * N)["x"].gen()
    f = x + (e * dpL + k - 1) * pow(2 ** dpL_bit_length * e, -1, k // g * N)
    X = 2 ** dp_unknown_msb
    logging.info(f"Trying {m = }, {t = }...")
    for x0, in howgrave_graham.modular_univariate(f, k * N, m, t, X):
        dp = int(f(x0))
        p = gcd(dp, N)
        if N % p == 0:
            return p, N // p


def attack_partial(N, e, partial_dp, partial_dq, m=None, t=None, check_bounds=True):
    """
    Recovers the prime factors from a modulus if the most or least significant bits of dp and dq are known.
    More information: Alexander M., Julian N., Santanu S., "Approximate Divisor Multiples - Factoring with Only a Third of the Secret CRT-Exponents"
    :param N: the modulus
    :param e: the exponent
    :param partial_dp: d mod (p - 1) (PartialInteger)
    :param partial_dq: d mod (q - 1) (PartialInteger)
    :param m: the parameter m for small roots (default: automatically calculated using beta = 0.5 and epsilon = 0.125)
    :param t: the parameter t for small roots (default: automatically calculated using beta = 0.5 and epsilon = 0.125)
    :param check_bounds: perform bounds check (default: True)
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    alpha = log(e, N)
    dp_bit_length = partial_dp.bit_length
    dq_bit_length = partial_dq.bit_length
    assert dp_bit_length == dq_bit_length, "dp and dq should be of equal bit length."

    beta = 0.5
    epsilon = 0.125
    m = ceil(max(beta ** 2 / epsilon, 7 * beta)) if m is None else m
    t = int((1 / beta - 1) * m) if t is None else t

    dpM, dpM_bit_length = partial_dp.get_known_msb()
    dqM, dqM_bit_length = partial_dq.get_known_msb()
    if dpM_bit_length > 0 and dqM_bit_length > 0:
        # Section 3.1.
        dp_unknown_lsb = partial_dp.get_unknown_lsb()
        dq_unknown_lsb = partial_dq.get_unknown_lsb()
        delta = log(max(2 ** dp_unknown_lsb, 2 ** dq_unknown_lsb), N)
        assert not check_bounds or delta < min(1 / 4 + alpha, 1 / 2 - 2 * alpha), f"Bounds check failed ({delta} < {min(1 / 4 + alpha, 1 / 2 - 2 * alpha)})."

        x = Zmod(e)["x"].gen()
        A_ = ceil_div(2 ** (dp_unknown_lsb + dq_unknown_lsb) * e ** 2 * dpM * dqM, N)

        # First case.
        f = x ** 2 - (1 - A_ * (N - 1)) * x + A_
        for k, _ in f.roots():
            if k == 0:
                continue

            factors = _factor_msb(N, e, dpM, dp_unknown_lsb, int(k), m, t)
            if factors:
                return factors
            factors = _factor_msb(N, e, dqM, dq_unknown_lsb, int(k), m, t)
            if factors:
                return factors

        # Second case.
        f = x ** 2 + (1 - A_ * (N - 1) + e) * x + A_
        for k, _ in f.roots():
            if k == 0:
                continue

            factors = _factor_msb(N, e, dpM, dp_unknown_lsb, int(k), m, t)
            if factors:
                return factors
            factors = _factor_msb(N, e, dqM, dq_unknown_lsb, int(k), m, t)
            if factors:
                return factors

    dpL, dpL_bit_length = partial_dp.get_known_lsb()
    dqL, dqL_bit_length = partial_dq.get_known_lsb()
    if dpL_bit_length > 0 and dqL_bit_length > 0:
        # Section 3.2.
        dp_unknown_msb = partial_dp.get_unknown_msb()
        dq_unknown_msb = partial_dq.get_unknown_msb()
        assert dpL_bit_length == dqL_bit_length, "dp and dq LSB should be of equal bit length."
        delta = log(max(2 ** dp_unknown_msb, 2 ** dq_unknown_msb), N)
        assert not check_bounds or delta < min(1 / 4 + alpha, 1 / 2 - 2 * alpha), f"Bounds check failed ({delta} < {min(1 / 4 + alpha, 1 / 2 - 2 * alpha)})."

        i = dpL_bit_length
        pr = Zmod(2 ** i * e)["x, y"]
        x, y = pr.gens()
        A = -e ** 2 * dpL * dqL + e * dpL + e * dqL - 1
        f = (N - 1) * x * y - (e * dqL - 1) * x - (e * dpL - 1) * y + A
        g = f * pow((N - 1) // gcd(N - 1, e * 2 ** i), -1, 2 ** i * e)
        for k, l in herrmann_may.modular_bivariate(g, 2 ** i * e, 2, 2, e, e):
            if k == 0 or l == 0:
                continue

            factors = _factor_lsb(N, e, dpL, dpL_bit_length, dp_unknown_msb, int(k), m, t)
            if factors:
                return factors
            factors = _factor_lsb(N, e, dqL, dqL_bit_length, dq_unknown_msb, int(l), m, t)
            if factors:
                return factors

    return None
