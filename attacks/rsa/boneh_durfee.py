import logging
import os
import sys

from sage.all import RR
from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi
from shared.small_roots import herrmann_may


def attack(N, e, bitsize, lsb_known=0, lsb=0, delta=0.25, m_start=1):
    """
    Recovers the prime factors if the private exponent is too small.
    This implementation exploits knowledge of least significant bits of prime factors, if available.
    More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
    :param N: the modulus
    :param e: the public exponent
    :param bitsize: the amount of bits of the prime factors
    :param lsb_known: the amount of known least significant bits of one of the prime factors
    :param lsb: the known least significant bits of one of the prime factors
    :param delta: a predicted bound on the private exponent (d < N^delta) (default: 0.25)
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the prime factors
    """
    x, y = Zmod(e)["x, y"].gens()

    # Use additional information about factors to speed up Boneh-Durfee
    p_lsb = lsb
    q_lsb = (pow(lsb, -1, 2 ** lsb_known) * (N % (2 ** lsb_known))) % (2 ** lsb_known)
    A = ((N >> lsb_known) + pow(2, -lsb_known, e) * (p_lsb * q_lsb - p_lsb - q_lsb + 1))
    f = x * (A + y) + pow(2, -lsb_known, e)

    X = int(e ** RR(delta))
    Y = int(2 ** (bitsize - lsb_known + 1))
    m = m_start
    while True:
        t = int((1 - 2 * delta) * m)
        logging.info(f"Trying m = {m}, t = {t}...")
        for x0, y0 in herrmann_may.modular_bivariate(f, e, m, t, X, Y):
            z = int(f(x0, y0))
            if z % e == 0:
                k = pow(x0, -1, e)
                s = (N + 1 + k) % e
                phi = N - s + 1
                factors = known_phi.factorize(N, phi)
                if factors:
                    return factors

        m += 1


def attack_multi_prime(N, e, bitsize, factors, delta=0.25, m_start=1):
    """
    Recovers the prime factors if the private exponent is too small.
    This method works for a modulus consisting of any number of primes.
    :param N: the modulus
    :param e: the public exponent
    :param bitsize: the amount of bits of the prime factors
    :param factors: the number of primes in the modulus
    :param delta: a predicted bound on the private exponent (d < n^delta) (default: 0.25)
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the prime factors
    """
    x, y = Zmod(e)["x, y"].gens()

    A = N + 1
    f = x * (A + y) + 1

    X = int(e ** RR(delta))
    Y = int(2 ** ((factors - 1) * bitsize + 1))
    m = m_start
    while True:
        t = int((1 - 2 * delta) * m)
        logging.info(f"Trying m = {m}, t = {t}...")
        for x0, y0 in herrmann_may.modular_bivariate(f, e, m, t, X, Y):
            z = int(f(x0, y0))
            if z % e == 0:
                k = pow(x0, -1, e)
                s = (N + 1 + k) % e
                phi = N - s + 1
                factors = known_phi.factorize_multi_prime(N, phi)
                if factors:
                    return factors

        m += 1
