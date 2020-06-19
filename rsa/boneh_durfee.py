import logging

from sage.all import PolynomialRing
from sage.all import RealNumber
from sage.all import Zmod

from small_roots.boneh_durfee import modular_bivariate


def attack(n, e, delta=0.25):
    """
    Recovers the private exponent if the private exponent is too small.
    More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
    :param n: the modulus
    :param e: the public exponent
    :param delta: a predicted bound on the private exponent (d < n^delta) (default: 0.25)
    :return: the private exponent
    """
    pr = PolynomialRing(Zmod(e), "x, y")
    x, y = pr.gens()
    a = (n + 1) // 2
    f = x * (a + y) + 1
    xbound = int(e ** RealNumber(delta))
    ybound = int(e ** RealNumber(0.5))
    m = 1
    while True:
        t = int(m * (1 - 2 * delta))
        logging.debug(f"Trying m = {m}, t = {t}...")
        for xroot, yroot in modular_bivariate(f, e, m, t, xbound, ybound):
            z = xroot * (a + yroot) + 1
            if z % e == 0:
                return z // e

        m += 1
