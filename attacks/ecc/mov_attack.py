import logging
from math import gcd

from sage.all import GF
from sage.all import discrete_log


def attack(P, R, max_k=6, max_tries=10):
    """
    Solves the discrete logarithm problem using the MOV attack.
    More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 2)
    :param P: the base point
    :param R: the point multiplication result
    :param max_k: the maximum value of embedding degree to try (default: 6)
    :param max_tries: the maximum amount of times to try to find l (default: 10)
    :return: l such that l * P == R, or None if l was not found
    """
    E = P.curve()
    q = E.base_ring().order()
    n = P.order()
    assert gcd(n, q) == 1, "GCD of generator order and curve base ring order should be 1."

    logging.info("Calculating embedding degree...")
    for k in range(1, max_k + 1):
        if q ** k % n == 1:
            break
    else:
        return None

    logging.info(f"Found embedding degree {k}")
    Ek = E.base_extend(GF(q ** k))
    Pk = Ek(P)
    Rk = Ek(R)
    for i in range(max_tries):
        Q_ = Ek.random_point()
        m = Q_.order()
        d = gcd(m, n)
        Q = (m // d) * Q_
        if Q.order() != n:
            continue

        alpha = Pk.weil_pairing(Q, n)
        if alpha == 1:
            continue

        beta = Rk.weil_pairing(Q, n)
        logging.info(f"Computing discrete_log({beta}, {alpha})...")
        l = discrete_log(beta, alpha)
        return int(l)

    return None
