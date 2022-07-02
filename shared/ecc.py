import logging
from random import choice
from random import randrange

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import hilbert_class_polynomial
from sage.all import is_prime
from sage.all import is_prime_power
from sage.all import kronecker
from sage.all import next_prime

from shared import is_square


def get_embedding_degree(q, n, max_k):
    """
    Returns the embedding degree k of an elliptic curve.
    Note: strictly speaking this function computes the Tate-embedding degree of a curve.
    In almost all cases, the Tate-embedding degree is the same as the Weil-embedding degree (also just called the "embedding degree").
    More information: Maas M., "Pairing-Based Cryptography" (Section 5.2)
    :param q: the order of the curve base ring
    :param n: the order of the base point
    :param max_k: the maximum value of embedding degree to try
    :return: the embedding degree k, or None if it was not found
    """
    for k in range(1, max_k + 1):
        if q ** k % n == 1:
            return k

    return None


def solve_cm(D, q, c=None):
    """
    Solves a Complex Multiplication equation for a given discriminant D, prime q, and parameter c.
    :param D: the CM discriminant
    :param q: the prime q
    :param c: an optional parameter c which is used to generate random a and b values (default: random element in Zmod(q))
    :return: a generator generating elliptic curves in Zmod(q) with random a and b values
    """
    assert is_prime_power(q)

    logging.debug(f"Solving CM equation for q = {q} using D = {D} and c = {c}")
    gf = GF(q)
    pr = gf["x"]
    H = pr(hilbert_class_polynomial(-D))
    ks = [j / (1728 - j) for j in H.roots(multiplicities=False)]
    while True:
        for k in ks:
            c_ = c if c is not None else gf.random_element()
            a = 3 * k * c_ ** 2
            b = 2 * k * c_ ** 3
            if a > 0 or b > 0:
                yield EllipticCurve(gf, [a, b])


def generate_anomalous(q=None, q_bit_length=None, D=None, c=None):
    """
    Generates random anomalous elliptic curves.
    More information: Leprevost F. et al., "Generating Anomalous Elliptic Curves"
    :param q: the finite field modulus (must be prime if provided)
    :param q_bit_length: the bit length of q, used to generate a random q if not provided
    :param D: the CM discriminant to use (default: randomly chosen from [11, 19, 43, 67, 163])
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random anomalous elliptic curves
    """
    Ds = [11, 19, 43, 67, 163] if D is None else [D]
    if q is None:
        assert q_bit_length is not None
        while True:
            D = choice(Ds)
            m_bit_length = (q_bit_length - D.bit_length()) // 2
            m = randrange(2 ** (m_bit_length - 1), 2 ** m_bit_length)
            q = D * m * (m + 1) + (D + 1) // 4
            if is_prime(q):
                break
        print(q, D)
    else:
        # Remove invalid Ds.
        Ds = [D for D in Ds if (4 * q - 1) % D == 0 and is_square((4 * q - 1) // D)]
        assert len(Ds) > 0, f"Invalid value for {q} and default values of D"
        D = choice(Ds)

    for E in solve_cm(D, q, c):
        if E.trace_of_frobenius() == 1:
            yield E
        else:
            E = E.quadratic_twist()
            yield E


def generate_supersingular(q, c=None):
    """
    Generates random supersingular elliptic curves.
    More information: Broker R., "Constructing Supersingular Elliptic Curves"
    :param q: a prime power q
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random supersingular elliptic curves
    """
    gfq = GF(q)
    p = gfq.characteristic()
    if p == 2:
        # E with j-invariant 0 are singular (Silverman, Arithmetic of Elliptic Curves, Appendix A).
        while True:
            a3 = gfq.random_element()
            a4 = gfq.random_element()
            a6 = gfq.random_element()
            if a3 > 0:
                yield EllipticCurve(gfq, [0, 0, a3, a4, a6])
    if p == 3:
        # E with j-invariant 0 are singular (Silverman, Arithmetic of Elliptic Curves, Appendix A).
        while True:
            a = gfq.random_element()
            b = gfq.random_element()
            if a > 0:
                yield EllipticCurve(gfq, [a, b])
    if p % 3 == 2:
        # E with j-invariant 0 are singular.
        while True:
            b = gfq.random_element()
            if b > 0:
                yield EllipticCurve(gfq, [0, b])
    if p % 4 == 3:
        # E with j-invariant 1728 are singular.
        while True:
            a = gfq.random_element()
            if a > 0:
                yield EllipticCurve(gfq, [a, 0])
    D = 3
    while D % 4 != 3 or kronecker(-D, p) != -1:
        D = next_prime(D)

    yield from solve_cm(D, q, c)
