from random import choice
from random import randrange

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import is_prime
from sage.all import kronecker
from sage.all import next_prime

from shared import is_square
from shared.complex_multiplication import solve_cm


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


def generate_anomalous_q(q, D=None, c=None):
    """
    Generates random anomalous elliptic curves for a specific modulus.
    More information: Leprevost F. et al., "Generating Anomalous Elliptic Curves"
    :param q: the prime finite field modulus
    :param D: the CM discriminant to use (default: randomly chosen from [-11, -19, -43, -67, -163])
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random anomalous elliptic curves
    """
    Ds = [-11, -19, -43, -67, -163] if D is None else [D]
    Ds = [D for D in Ds if (1 - 4 * q) % D == 0 and is_square((1 - 4 * q) // D)]
    assert len(Ds) > 0, "Invalid value for q and default values of D."
    D = choice(Ds)
    for E in solve_cm(D, q, c):
        if E.trace_of_frobenius() == 1:
            yield E
        else:
            E = E.quadratic_twist()
            yield E


def generate_anomalous(q_bit_length, D=None, c=None):
    """
    Generates random anomalous elliptic curves for a specific modulus bit length.
    More information: Leprevost F. et al., "Generating Anomalous Elliptic Curves"
    :param q_bit_length: the bit length of the modulus, used to generate a random q
    :param D: the CM discriminant to use (default: randomly chosen from [-11, -19, -43, -67, -163])
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random anomalous elliptic curves
    """
    Ds = [-11, -19, -43, -67, -163] if D is None else [D]
    while True:
        D = choice(Ds)
        m_bit_length = (q_bit_length - D.bit_length()) // 2 + 1
        m = randrange(2 ** (m_bit_length - 1), 2 ** m_bit_length)
        q = -D * m * (m + 1) + (-D + 1) // 4
        if is_prime(q) and q.bit_length() == q_bit_length:
            yield from generate_anomalous_q(q, D, c)


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

    yield from solve_cm(-D, q, c)
