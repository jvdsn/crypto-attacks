import logging
import os
import sys
from math import gcd

from sage.all import GF
from sage.all import crt
from sage.all import is_prime

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi
from shared import rth_roots


def attack(N, e, phi, c):
    """
    Computes possible plaintexts when e is not coprime with Euler's totient.
    More information: Shumow D., "Incorrectly Generated RSA Keys: How To Recover Lost Plaintexts"
    :param N: the modulus
    :param e: the public exponent
    :param phi: Euler's totient for the modulus
    :param c: the ciphertext
    :return: a generator generating possible plaintexts for c
    """
    assert phi % e == 0, "Public exponent must divide Euler's totient"
    assert is_prime(e), "Public exponent must be prime"
    if gcd(phi // e, e) == 1:
        phi //= e
        # Finding multiplicative generator of subgroup with order e elements (Algorithm 1).
        g = 1
        gE = 1
        while gE == 1:
            g += 1
            gE = pow(g, phi, N)

        # Finding possible plaintexts (Algorithm 2).
        d = pow(e, -1, phi)
        a = pow(c, d, N)
        l = gE
        for i in range(e):
            x = a * l % N
            l = l * gE % N
            yield x
    else:
        # Fall back to more generic root finding using Adleman-Manders-Miller and CRT.
        p, q = known_phi.factorize(N, phi)
        tp = 0
        while (p - 1) % (e ** (tp + 1)) == 0:
            tp += 1
        tq = 0
        while (q - 1) % (e ** (tq + 1)) == 0:
            tq += 1

        assert tp > 0 or tq > 0
        cp = c % p
        cq = c % q
        logging.info(f"Computing {e}-th roots mod {p}...")
        mps = [pow(cp, pow(e, -1, p - 1), p)] if tp == 0 else list(rth_roots(GF(p), cp, e))
        logging.info(f"Computing {e}-th roots mod {q}...")
        mqs = [pow(cq, pow(e, -1, q - 1), q)] if tq == 0 else list(rth_roots(GF(q), cq, e))
        logging.info(f"Computing {len(mps) * len(mqs)} roots using CRT...")
        for mp in mps:
            for mq in mqs:
                yield int(crt([mp, mq], [p, q]))
