import logging

from sage.all import PolynomialRing
from sage.all import RealNumber
from sage.all import ZZ
from sage.all import Zmod

from small_roots.boneh_durfee import modular_bivariate


def attack(n, e, bitsize, lsb_known=0, lsb=0, delta=0.25):
    """
    Recovers the prime factors if the private exponent is too small.
    More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
    This implementation exploits knowledge of least significant bits of prime factors, if available.
    :param n: the modulus
    :param e: the public exponent
    :param bitsize: the amount of bits of the prime factors
    :param lsb_known: the amount of known least significant bits of one of the prime factors
    :param lsb: the known least significant bits of one of the prime factors
    :param delta: a predicted bound on the private exponent (d < n^delta) (default: 0.25)
    :return: a tuple containing the prime factors
    """
    x, y = PolynomialRing(Zmod(e), "x, y").gens()

    # Use additional information about factors to speed up Boneh-Durfee
    p_lsb = lsb
    q_lsb = (pow(lsb, -1, 2 ** lsb_known) * (n % 2 ** lsb_known)) % (2 ** lsb_known)
    a = ((n >> lsb_known) + pow(2, -lsb_known, e) * (p_lsb * q_lsb - p_lsb - q_lsb + 1))
    f = x * (a + y) + pow(2, -lsb_known, e)

    xbound = int(e ** RealNumber(delta))
    ybound = int(2 ** (bitsize - lsb_known + 1))
    m = 1
    while True:
        t = int(m * (1 - 2 * delta))
        logging.debug(f"Trying m = {m}, t = {t}...")
        for xroot, yroot in modular_bivariate(f, e, m, t, xbound, ybound):
            z = xroot * (a + yroot) + pow(2, -lsb_known, e)
            if z % e == 0:
                s = (n + 1 + pow(xroot, -1, e)) % e
                p = PolynomialRing(ZZ, "p").gen()
                f = p ** 2 - s * p + n
                for proot, _ in f.roots():
                    proot = int(proot)
                    if n % proot == 0:
                        return proot, n // proot

        m += 1
