import logging
from math import gcd

from sage.all import GF
from sage.all import discrete_log


def attack(P, R, max_k=6, max_tries=10):
    """
    Solves the discrete logarithm problem using the Frey-Ruck attack.
    More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 3)
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
    for _ in range(max_tries):
        S = Ek.random_point()
        T = Ek.random_point()
        gamma = Pk.tate_pairing(S, n, k) / Pk.tate_pairing(T, n, k)
        if gamma == 1:
            continue

        delta = Rk.tate_pairing(S, n, k) / Rk.tate_pairing(T, n, k)
        logging.info(f"Computing discrete_log({delta}, {gamma})...")
        l = discrete_log(delta, gamma)
        return int(l)

    return None
