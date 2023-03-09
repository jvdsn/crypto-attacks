import logging
import os
import sys
from math import ceil
from math import gcd
from math import sqrt

from sage.all import QQ
from sage.all import RR
from sage.all import ZZ
from sage.all import Zmod
from sage.all import is_prime

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi
from shared.hensel import hensel_roots
from shared.small_roots import blomer_may
from shared.small_roots import ernst
from shared.small_roots import howgrave_graham


def _bdf_corollary_1(e, f, N, m, t, X):
    for x0, in howgrave_graham.modular_univariate(f, N, m, t, X):
        p = int(f(x0))
        if 1 < p < N and N % p == 0:
            q = N // p
            phi = (p - 1) * (q - 1)
            yield p, q, pow(e, -1, phi)


def _bdf_theorem_6(N, e, d_bit_length, d1, d1_bit_length):
    d0 = d1 << (d_bit_length - d1_bit_length)
    k_ = (e * d0 - 1) // N
    logging.info("Generating solutions for k candidates...")
    for k in range(k_ - 40, k_ + 40):
        yield d0, k


def _bdf_3(N, e, d_bit_length, d0, d0_bit_length, r, m, t):
    n = N.bit_length()
    logging.info(f"Trying m = {m}, t = {t}...")
    p = ZZ["p"].gen()
    x = Zmod(N)["x"].gen()
    X = int(2 * RR(N) ** (1 / 2) / r)  # Equivalent to 2^(n / 2 + 1) / r
    logging.info("Generating solutions for k candidates...")
    for k in range(1, e):
        f = k * p ** 2 + (e * d0 - (1 + k * (N + 1))) * p + k * N
        for p0 in hensel_roots(f, 2, d0_bit_length):
            f = x * r + p0
            for p_, q_, d_ in _bdf_corollary_1(e, f, N, m, t, X):
                return p_, q_, d_

    return None


def _bdf_4_1(N, e, d_bit_length, d1, d1_bit_length, m, t):
    logging.info(f"Trying m = {m}, t = {t}...")
    p = Zmod(e)["p"].gen()
    x = Zmod(N)["x"].gen()
    X = int(2 * RR(N) ** (1 / 2) / e)  # Equivalent to 2^(n / 2 + 1) / e
    for _, k in _bdf_theorem_6(N, e, d_bit_length, d1, d1_bit_length):
        f = k * p ** 2 - (1 + k * (N + 1)) * p + k * N
        for p0 in f.roots(multiplicities=False):
            f = x * e + int(p0)
            for p_, q_, d_ in _bdf_corollary_1(e, f, N, m, t, X):
                return p_, q_, d_

    return None


def _bdf_4_2(N, e, d_bit_length, d1, d1_bit_length):
    for d0, k in _bdf_theorem_6(N, e, d_bit_length, d1, d1_bit_length):
        if gcd(e, k) != 1:
            continue

        d1 = pow(e, -1, k)
        for v in range(ceil(e / k) + 1):
            d2 = int(QQ(d0) / k + v - QQ(d1) / k)
            d = k * d2 + d1
            if pow(pow(2, e, N), d, N) == 2:
                phi = (e * d - 1) // k
                factors = known_phi.factorize(N, phi)
                if factors:
                    return *factors, d

    return None


def _bdf_4_3(N, e, d_bit_length, d0, d0_bit_length, d1, d1_bit_length, r, m, t):
    logging.info(f"Trying m = {m}, t = {t}...")
    p = ZZ["p"].gen()
    x = Zmod(N)["x"].gen()
    X = int(2 * RR(N) ** (1 / 2) / r)  # Equivalent to 2^(n / 2 + 1) / r
    for _, k in _bdf_theorem_6(N, e, d_bit_length, d1, d1_bit_length):
        f = k * p ** 2 + (e * d0 - (1 + k * (N + 1))) * p + k * N
        for p0 in hensel_roots(f, 2, d0_bit_length):
            f = x * r + p0
            for p_, q_, d_ in _bdf_corollary_1(e, f, N, m, t, X):
                return p_, q_, d_

    return None


def _bm_4(N, e, d_bit_length, d1, d1_bit_length, m, t):
    d_ = d1 << (d_bit_length - d1_bit_length)
    k_ = (e * d_ - 1) // (N + 1)

    x, y, z = ZZ["x", "y", "z"].gens()
    f = e * x + (k_ + y) * z + e * d_ - 1
    X = 2 ** (d_bit_length - d1_bit_length)  # Equivalent to N^delta
    Y = int(4 * e / RR(N) ** (1 / 2))  # Equivalent to 4N^(alpha - 1 / 2)
    Z = int(3 * RR(N) ** (1 / 2))
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0, z0 in blomer_may.modular_trivariate(f, N, m, t, X, Y, Z):
        d = d_ + x0
        phi = N - z0
        if pow(pow(2, e, N), d, N) == 2:
            factors = known_phi.factorize(N, phi)
            if factors:
                return *factors, d

    return None


def _bm_6(N, e, d_bit_length, d0, d0_bit_length, M, m, t):
    y, z = ZZ["y", "z"].gens()
    f = y * (N - z) - e * d0 + 1
    Y = e  # Equivalent to N^alpha
    Z = int(3 * RR(N) ** (1 / 2))
    logging.info(f"Trying m = {m}, t = {t}...")
    for y0, z0 in blomer_may.modular_bivariate(f, e * M, m, t, Y, Z):
        phi = N - z0
        d = pow(e, -1, phi)
        if pow(pow(2, e, N), d, N) == 2:
            factors = known_phi.factorize(N, phi)
            if factors:
                return *factors, d

    return None


def _ernst_4_1_1(N, e, d_bit_length, d1, d1_bit_length, m, t):
    d_ = d1 << (d_bit_length - d1_bit_length)
    R = e * d_ - 1

    x, y, z = ZZ["x", "y", "z"].gens()
    f = e * x - N * y + y * z + R
    X = 2 ** (d_bit_length - d1_bit_length)  # Equivalent to N^delta
    Y = 2 ** d_bit_length  # Equivalent to N^beta
    Z = int(3 * RR(N) ** (1 / 2))
    W = N * Y
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0, z0 in ernst.integer_trivariate_1(f, m, t, W, X, Y, Z):
        d = d_ + x0
        phi = N - z0
        if pow(pow(2, e, N), d, N) == 2:
            factors = known_phi.factorize(N, phi)
            if factors:
                return *factors, d

    return None


def _ernst_4_1_2(N, e, d_bit_length, d1, d1_bit_length, m, t):
    d_ = d1 << (d_bit_length - d1_bit_length)
    k_ = (e * d_ - 1) // N
    R = e * d_ - 1 - k_ * N

    x, y, z = ZZ["x", "y", "z"].gens()
    f = e * x - N * y + y * z + k_ * z + R
    X = 2 ** (d_bit_length - d1_bit_length)  # Equivalent to N^delta
    Y = 4 * int(max(2 ** (d_bit_length - d1_bit_length), 2 ** d_bit_length / RR(N) ** (1 / 2)))  # Equivalent to 4N^max(delta, beta - 1 / 2)
    Z = int(3 * RR(N) ** (1 / 2))
    W = N * Y
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0, z0 in ernst.integer_trivariate_2(f, m, t, W, X, Y, Z):
        d = d_ + x0
        phi = N - z0
        if pow(pow(2, e, N), d, N) == 2:
            factors = known_phi.factorize(N, phi)
            if factors:
                return *factors, d

    return None


def _ernst_4_2(N, e, d_bit_length, d1, d1_bit_length, m, t):
    d_ = d1 << (d_bit_length - d1_bit_length)
    k_ = (e * d_ - 1) // N
    R = e * d_ - 1 - k_ * N

    x, y, z = ZZ["x", "y", "z"].gens()
    f = e * x - N * y + y * z + k_ * z + R
    X = 2 ** (d_bit_length - d1_bit_length)  # Equivalent to N^delta
    Y = 4 * int(max((e * 2 ** (d_bit_length - d1_bit_length)) / N, e / RR(N) ** (1 / 2)))  # Equivalent to 4N^max(alpha + delta - 1, alpha - 1 / 2)
    Z = int(3 * RR(N) ** (1 / 2))
    W = N * Y
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0, z0 in ernst.integer_trivariate_2(f, m, t, W, X, Y, Z):
        d = d_ + x0
        phi = N - z0
        if pow(pow(2, e, N), d, N) == 2:
            factors = known_phi.factorize(N, phi)
            if factors:
                return *factors, d

    return None


def _ernst_4_3(N, e, d_bit_length, d0, d0_bit_length, M, m, t):
    R = e * d0 - 1

    x, y, z = ZZ["x", "y", "z"].gens()
    f = e * M * x - N * y + y * z + R
    X = 2 ** (d_bit_length - d0_bit_length)  # Equivalent to N^delta
    Y = 2 ** d_bit_length  # Equivalent to N^beta
    Z = int(3 * RR(N) ** (1 / 2))
    W = N * Y
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0, z0 in ernst.integer_trivariate_1(f, m, t, W, X, Y, Z):
        d = x0 * M + d0
        phi = N - z0
        if pow(pow(2, e, N), d, N) == 2:
            factors = known_phi.factorize(N, phi)
            if factors:
                return *factors, d

    return None


def attack(N, e, partial_d, factor_e=True, m=1, t=None):
    """
    Recovers the prime factors of a modulus and the private exponent if part of the private exponent is known.
    More information: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits"
    More information: Blomer J., May A., "New Partial Key Exposure Attacks on RSA"
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents"
    :param N: the modulus
    :param e: the public exponent
    :param partial_d: the partial private exponent d (PartialInteger)
    :param factor_e: whether we should attempt to factor e (for BDF) if it is not prime (default: True)
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: automatically computed using m)
    :return: a tuple containing the prime factors and the private exponent, or None if the private exponent was not found
    """
    d_bit_length = partial_d.bit_length
    d0, d0_bit_length = partial_d.get_known_lsb()
    d1, d1_bit_length = partial_d.get_known_msb()
    assert d0_bit_length > 0 or d1_bit_length > 0, "At least some lsb or msb of d must be known."

    n = N.bit_length()
    # Subtract one here, because 2^t < e < 2^(t + 1).
    t_ = e.bit_length() - 1
    alpha = t_ / n
    beta = d_bit_length / n
    assert beta >= 0.25, "Use Wiener's or the Boneh-Durfee attack if d is very small."

    if d0_bit_length > 0 and d1_bit_length > 0:
        # Known lsbs and msbs.
        M = 2 ** d0_bit_length

        if 1 <= t_ <= n / 2 and d0_bit_length >= n / 4 and d1_bit_length >= t_:
            logging.info("Using Boneh-Durfee-Frankel (Section 4.3)...")
            assert t is not None, "t can not be None for Boneh-Durfee-Frankel small roots."
            return _bdf_4_3(N, e, d_bit_length, d0, d0_bit_length, d1, d1_bit_length, M, m, t)

        logging.info("No attacks were found to fit the provided parameters (known lsbs and msbs).")
        return None

    if d0_bit_length > 0:
        # Known lsbs.
        M = 2 ** d0_bit_length
        delta = (d_bit_length - d0_bit_length) / n

        if e < RR(N) ** (7 / 8) and RR(N) ** (1 / 6 + 1 / 3 * sqrt(1 + 6 * alpha)) <= M:
            logging.info("Using Blomer-May (Section 6)...")
            t = int((2 / 3 * (1 - delta - alpha) / (2 * alpha - 1))) if t is None else t
            return _bm_6(N, e, d_bit_length, d0, d0_bit_length, M, m, t)

        if delta <= 5 / 6 - 1 / 3 * sqrt(1 + 6 * beta):
            logging.info("Using Ernst (Section 4.3)...")
            t = int((1 / 2 - delta) * m) if t is None else t
            return _ernst_4_3(N, e, d_bit_length, d0, d0_bit_length, M, m, t)

        # Last resort method: enumerate possible k values (very slow if e is too large).
        if d0_bit_length >= n / 4:
            logging.info("Using Boneh-Durfee-Frankel (Section 3)...")
            assert t is not None, "t can not be None for Boneh-Durfee-Frankel small roots."
            return _bdf_3(N, e, d_bit_length, d0, d0_bit_length, M, m, t)

        logging.info("No attacks were found to fit the provided parameters (known lsbs).")
        return None

    if d1_bit_length > 0:
        delta = (d_bit_length - d1_bit_length) / n

        if n / 4 <= t_ <= n / 2 and d1_bit_length >= t_ and (is_prime(e) or factor_e):
            logging.info("Using Boneh-Durfee-Frankel (Section 4.1)...")
            assert t is not None, "t can not be None for Boneh-Durfee-Frankel small roots."
            return _bdf_4_1(N, e, d_bit_length, d1, d1_bit_length, m, t)

        if 0 <= t_ <= n / 2 and d1_bit_length >= n - t_:
            logging.info("Using Boneh-Durfee-Frankel (Section 4.2)...")
            return _bdf_4_2(N, e, d_bit_length, d1, d1_bit_length)

        # Blomer-May Section 4 is superseded by Ernst Section 4.2.
        # if 1 / 2 < alpha <= (sqrt(6) - 1) / 2 and delta <= 1 / 8 * (5 - 2 * alpha - sqrt(36 * alpha ** 2 + 12 * alpha - 15)):
        #     logging.info("Using Blomer-May (Section 4)...")
        #     t = int((2 / 3 * (1 - delta - alpha) / (2 * alpha - 1))) if t is None else t
        #     return _bm_4(N, e, d_bit_length, d1, d1_bit_length, m, t)

        margin4_1_1 = 5 / 6 - 1 / 3 * sqrt(1 + 6 * beta) - delta
        margin4_1_2 = (3 / 16 - delta) if beta <= 11 / 16 else (1 / 3 + 1 / 3 * beta - 1 / 3 * sqrt(4 * beta ** 2 + 2 * beta - 2) - delta)
        if margin4_1_1 > max(0, margin4_1_2):
            logging.info("Using Ernst (Section 4.1.1)...")
            t = int((1 / 2 - delta) * m) if t is None else t
            return _ernst_4_1_1(N, e, d_bit_length, d1, d1_bit_length, m, t)

        if margin4_1_2 > max(0, margin4_1_1):
            logging.info("Using Ernst (Section 4.1.2)...")
            gamma = max(delta, beta - 1 / 2)
            t = int(((1 / 2 - delta - gamma) / (2 * gamma)) * m) if t is None else t
            return _ernst_4_1_2(N, e, d_bit_length, d1, d1_bit_length, m, t)

        if alpha > 1 / 2 and delta <= 1 / 3 + 1 / 3 * alpha - 1 / 3 * sqrt(4 * alpha ** 2 + 2 * alpha - 2):
            logging.info("Using Ernst (Section 4.2)...")
            gamma = max(alpha + delta - 1, alpha - 1 / 2)
            t = int(((1 / 2 - delta - gamma) / (2 * gamma)) * m) if t is None else t
            return _ernst_4_2(N, e, d_bit_length, d1, d1_bit_length, m, t)

        logging.info("No attacks were found to fit the provided parameters (known msbs).")
        return None

    logging.info("No attacks were found to fit the provided parameters.")
    return None
