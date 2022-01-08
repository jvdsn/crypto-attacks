import logging
import os
import sys
from math import ceil
from math import gcd
from math import log
from math import sqrt

from sage.all import QQ
from sage.all import RR
from sage.all import ZZ
from sage.all import Zmod
from sage.all import is_prime

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.hensel import hensel_roots
from shared.small_roots import blomer_may
from shared.small_roots import ernst
from shared.small_roots import howgrave_graham


def attack_very_small_e_msb(N, e, d_, d__known, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the public exponent is "small".
    More information: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits" (Section 4)
    :param N: the modulus
    :param e: the public exponent
    :param d_: the most significant bits of the private exponent
    :param d__known: the amount of known most significant bits of the private exponent
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    k_ = (e * d_ - 1) // N
    if is_prime(e):
        assert RR(N) ** (1 / 4) <= 2 ** d__known <= RR(N) ** (1 / 2), "At least 1/4 and at most 1/2 of the most significant bits of d are required."

        logging.info("Generating solutions for k candidates...")
        p = Zmod(e)["p"].gen()
        p0s = set()
        for k in range(k_ - 40, k_ + 40):
            f = k * p ** 2 - (k * N + k + 1) * p + k * N
            for p0 in f.roots(multiplicities=False):
                p0s.add(int(p0))

        x = Zmod(N)["x"].gen()
        X = 2 ** (ceil(log(N, 2) / 2) - d__known)
        m = m_start
        while True:
            t = m
            logging.info(f"Trying m = {m}, t = {t}...")
            for p0 in p0s:
                f = x * e + p0
                for x0, in howgrave_graham.modular_univariate(f, N, m, t, X):
                    p = int(f(x0))
                    if p != 0 and N % p == 0:
                        q = N // p
                        phi = (p - 1) * (q - 1)
                        return pow(e, -1, phi), phi

            m += 1
    else:
        assert 2 ** d__known >= RR(N) ** (1 / 2), "At least 1/2 of the most significant bits of d are required."

        logging.info("Generating solutions for k candidates...")
        for k in range(k_ - 40, k_ + 40):
            if gcd(e, k) != 1:
                continue

            d1 = pow(e, -1, k)
            for v in range(ceil(e / k) + 1):
                d2 = int(QQ(d_) / k + 3 - QQ(d1) / k)
                d = k * d2 + d1
                if pow(pow(2, e, N), d, N) == 2:
                    phi = (e * d - 1) // k
                    return d, phi


def attack_very_small_e_lsb(N, e, d0, d0_known, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the public exponent is "small".
    More information: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits" (Section 3)
    :param N: the modulus
    :param e: the public exponent (should be enumerable)
    :param d0: the least significant bits of the private exponent
    :param d0_known: the amount of known least significant bits of the private exponent
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    assert RR(N) ** (1 / 4) <= 2 ** d0_known, "At least 1/4 of the least significant bits of d are required."

    logging.info("Generating solutions for k candidates...")
    p = ZZ["p"].gen()
    p0s = set()
    for k in range(1, e + 1):
        f = k * p ** 2 + (e * d0 - (k * N + k + 1)) * p + k * N
        for p0 in hensel_roots(f, 2, d0_known):
            p0s.add(p0)

    x = Zmod(N)["x"].gen()
    X = 2 ** (ceil(log(N, 2) / 2) - d0_known)
    m = m_start
    while True:
        t = m
        logging.info(f"Trying m = {m}, t = {t}...")
        for p0 in p0s:
            f = x * 2 ** d0_known + p0
            for x0, in howgrave_graham.modular_univariate(f, N, m, t, X):
                p = int(f(x0))
                if p != 0 and N % p == 0:
                    q = N // p
                    phi = (p - 1) * (q - 1)
                    return pow(e, -1, phi), phi

        m += 1


def attack_small_e_msb(N, e, d_, delta, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the public exponent is "small".
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents" (Section 4.2)
    :param N: the modulus
    :param e: the public exponent
    :param d_: the most significant bits of the private exponent (d = d_ + d0)
    :param delta: d0 <= N^delta
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    alpha = log(e, N)
    assert alpha >= 1 / 2
    assert delta <= 1 / 3 + 1 / 3 * alpha - 1 / 3 * sqrt(4 * alpha ** 2 * 2 * alpha - 2), "Bound check failed."

    x, y, z = ZZ["x, y, z"].gens()

    k_ = int(QQ(e * d_ - 1) / N)
    R = e * d_ - 1 - k_ * N
    f = e * x - N * y + y * z + k_ * z + R

    gamma = max(alpha + delta - 1, alpha - 1 / 2)

    X = int(RR(N) ** delta)
    Y = int(4 * RR(N) ** gamma)
    Z = int(3 * RR(N) ** (1 / 2))
    W = int(RR(N) ** (1 + gamma))

    m = m_start
    while True:
        for t in range(m + 1):
            logging.info(f"Trying m = {m}, t = {t}...")
            for x0, y0, z0 in ernst.integer_trivariate_2(f, m, t, W, X, Y, Z):
                d = d_ + x0
                phi = N - z0
                if pow(pow(2, e, N), d, N) == 2:
                    return d, phi

        m += 1


def attack_small_e_lsb(N, e, d0, M, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the public exponent is "small".
    More information: Blomer J., May A., "New Partial Key Exposure Attacks on RSA" (Section 6)
    :param N: the modulus
    :param e: the public exponent
    :param d0: the least significant bits of the private exponent (d = d0 mod M)
    :param M: the multiplier of the most significant bits of the private exponent (d = d0 mod M)
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    alpha = log(e, N)
    assert alpha <= 7 / 8, "Bound check failed."
    assert M >= N ** (1 / 6 + 1 / 3 * sqrt(1 + 6 * alpha)), "Bound check failed."

    y, z = ZZ["y, z"].gens()

    f = y * (N - z) - e * d0 + 1

    Y = int(RR(N) ** alpha)
    Z = int(3 * RR(N) ** (1 / 2))

    m = m_start
    while True:
        for t in range(m + 1):
            logging.info(f"Trying m = {m}, t = {t}...")
            for y0, z0 in blomer_may.modular_bivariate(f, e, M, m, t, Y, Z):
                phi = N - z0
                d = pow(e, -1, phi)
                if pow(pow(2, e, N), d, N) == 2:
                    return d, phi

        m += 1


def attack_small_d_msb_1(N, e, d_, beta, delta, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the private exponent is "small".
    This method uses f_MSB1.
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents" (Section 4.1.1)
    :param N: the modulus
    :param e: the public exponent
    :param d_: the most significant bits of the private exponent (d = d_ + d0)
    :param beta: d <= N^beta
    :param delta: d0 <= N^delta
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    assert delta <= 5 / 6 - 1 / 3 * sqrt(1 + 6 * beta), "Bound check failed."

    x, y, z = ZZ["x, y, z"].gens()

    R = e * d_ - 1
    f = e * x - N * y + y * z + R

    X = int(RR(N) ** delta)
    Y = int(RR(N) ** beta)
    Z = int(3 * RR(N) ** (1 / 2))
    W = int(RR(N) ** (1 + beta))

    m = m_start
    while True:
        for t in range(m + 1):
            logging.info(f"Trying m = {m}, t = {t}...")
            for x0, y0, z0 in ernst.integer_trivariate_1(f, m, t, W, X, Y, Z):
                d = d_ + x0
                phi = N - z0
                if pow(pow(2, e, N), d, N) == 2:
                    return d, phi

        m += 1


def attack_small_d_msb_2(N, e, d_, beta, delta, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the private exponent is "small".
    This method uses f_MSB2.
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents" (Section 4.1.2)
    :param N: the modulus
    :param e: the public exponent
    :param d_: the most significant bits of the private exponent (d = d_ + d0)
    :param beta: d <= N^beta
    :param delta: d0 <= N^delta
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    assert (delta <= 3 / 16 and beta <= 11 / 16) or (delta <= 1 / 3 + 1 / 3 * beta - 1 / 3 * sqrt(4 * beta ** 2 + 2 * beta - 2) and beta >= 11 / 16), "Bound check failed."

    x, y, z = ZZ["x, y, z"].gens()

    k_ = int(QQ(e * d_ - 1) / N)
    R = e * d_ - 1 - k_ * N
    f = e * x - N * y + y * z + k_ * z + R

    gamma = max(delta, beta - 1 / 2)

    X = int(RR(N) ** delta)
    Y = int(4 * RR(N) ** gamma)
    Z = int(3 * RR(N) ** (1 / 2))
    W = int(4 * RR(N) ** (1 + gamma))

    m = m_start
    while True:
        for t in range(m + 1):
            logging.info(f"Trying m = {m}, t = {t}...")
            for x0, y0, z0 in ernst.integer_trivariate_2(f, m, t, W, X, Y, Z):
                d = d_ + x0
                phi = N - z0
                if pow(pow(2, e, N), d, N) == 2:
                    return d, phi

        m += 1


def attack_small_d_lsb(N, e, d0, M, beta, delta, m_start=1):
    """
    Recovers the private exponent and phi if part of the private exponent is known and the private exponent is "small".
    This method uses f_LSB.
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents" (Section 4.3)
    :param N: the modulus
    :param e: the public exponent
    :param d0: the least significant bits of the private exponent (d = d1 * M + d0)
    :param M: the multiplier of the most significant bits of the private exponent (d = d1 * M + d0)
    :param beta: d <= N^beta
    :param delta: d1 <= N^delta
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the private exponent and phi
    """
    assert delta <= 5 / 6 - 1 / 3 * sqrt(1 + 6 * beta), "Bound check failed."

    x, y, z = ZZ["x, y, z"].gens()

    R = e * d0 - 1
    f = e * M * x - N * y + y * z + R

    X = int(RR(N) ** delta)
    Y = int(RR(N) ** beta)
    Z = int(3 * RR(N) ** (1 / 2))
    W = int(RR(N) ** (1 + beta))

    m = m_start
    while True:
        for t in range(m + 1):
            logging.info(f"Trying m = {m}, t = {t}...")
            for x0, y0, z0 in ernst.integer_trivariate_1(f, m, t, W, X, Y, Z):
                d = x0 * M + d0
                phi = N - z0
                if pow(pow(2, e, N), d, N) == 2:
                    return d, phi

        m += 1
