import logging
from math import isqrt
from random import choice
from random import randrange

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import factor
from sage.all import is_prime
from sage.all import kronecker
from sage.all import next_prime
from sage.all import pari

from shared import is_square
from shared import make_square_free
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
    :param D: the (negative) CM discriminant to use (default: randomly chosen from [-11, -19, -43, -67, -163])
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
    :param D: the (negative) CM discriminant to use (default: randomly chosen from [-11, -19, -43, -67, -163])
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


def generate_with_trace_q(t, q, D=None, c=None):
    """
    Generates random elliptic curves for a specific trace of Frobenius and modulus.
    Note: this method may take a very long time if D is not provided.
    :param t: the trace of Frobenius
    :param q: the prime finite field modulus
    :param D: the (negative) CM discriminant to use (default: computed using t and q)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    assert abs(t) <= 2 * isqrt(q), "Invalid values for t and q"

    if D is None:
        D = t ** 2 - 4 * q
        D = make_square_free(D, factor(D))
    else:
        assert (t ** 2 - 4 * q) % D == 0 and is_square((t ** 2 - 4 * q) // D), "Invalid values for t, q, and D."

    for E in solve_cm(D, q, c):
        if E.trace_of_frobenius() == t:
            yield E
        else:
            E = E.quadratic_twist()
            yield E


def generate_with_trace(t, q_bit_length, D=None, c=None):
    """
    Generates random elliptic curves for a specific trace of Frobenius and modulus bit length.
    :param t: the trace of Frobenius
    :param q_bit_length: the bit length of the modulus, used to generate a random q
    :param D: the (negative) CM discriminant to use (default: computed using t)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    if D is None:
        D = 11
        while D % 4 != 3 or t % D == 0:
            D = next_prime(D)
        D = int(-D)
        logging.info(f"Found appropriate D value = {D}")
    else:
        assert (-D) % 4 == 3 and t % (-D) != 0 and is_prime(-D), "Invalid values for t and D."

    v_bit_length = (q_bit_length + 2 - D.bit_length()) // 2 + 1
    assert v_bit_length > 0, "Invalid values for t and q bit length."

    while True:
        v = randrange(2 ** (v_bit_length - 1), 2 ** v_bit_length)
        q4 = t ** 2 - v ** 2 * D
        if q4 % 4 == 0 and is_prime(q4 // 4) and q4.bit_length() - 2 == q_bit_length:
            q = q4 // 4
            yield from generate_with_trace_q(t, q, D, c)


def generate_with_order_q(m, q, D=None, c=None):
    """
    Generates random elliptic curves for a specific order and modulus.
    Note: this method may take a very long time if D is not provided.
    :param m: the order
    :param q: the prime finite field modulus
    :param D: the (negative) CM discriminant to use (default: computed using m and q)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    yield from generate_with_trace_q(q + 1 - m, q, D, c)


def generate_with_order(m, D=None, c=None):
    """
    Generates random elliptic curves for a specific order.
    The modulus bit length will always be approximately equal to the order bit length.
    Based on: Broeker R., Stevenhagen P., "Constructing Elliptic Curves of Prime Order"
    :param m: the order
    :param D: the (negative) CM discriminant to use (default: computed using m)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    if D is None:
        D = -5
        while True:
            if D % 4 == 0 or D % 4 == 1:
                if -D >= 4 * m:
                    logging.info(f"Unable to find appropriate D value for m = {m}")
                    return

                found = False
                # TODO: use qfbcornacchia when PARI 2.14.0 is released.
                for sols in pari.qfbsolve(pari.Qfb(1, 0, -D), 4 * m, 1):
                    t = int(sols[0])
                    if is_prime(m + 1 - t) or is_prime(m + 1 + t):
                        found = True
                        break
                if found:
                    break
            D -= 1
        logging.info(f"Found appropriate D value = {D}")
    else:
        found = False
        # TODO: use qfbcornacchia when PARI 2.14.0 is released.
        for sols in pari.qfbsolve(pari.Qfb(1, 0, -D), 4 * m, 1):
            t = int(sols[0])
            if is_prime(m + 1 - t) or is_prime(m + 1 + t):
                found = True
                break

        assert found, "Invalid values for m and D."

    q = m + 1 - t if is_prime(m + 1 - t) else m + 1 + t
    for E in solve_cm(D, q, c):
        if E.order() == m:
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
    gf = GF(q)
    p = gf.characteristic()
    if p == 2:
        # E with j-invariant 0 are singular (Silverman, Arithmetic of Elliptic Curves, Appendix A).
        while True:
            a3 = gf.random_element()
            a4 = gf.random_element()
            a6 = gf.random_element()
            if a3 > 0:
                yield EllipticCurve(gf, [0, 0, a3, a4, a6])
    if p == 3:
        # E with j-invariant 0 are singular (Silverman, Arithmetic of Elliptic Curves, Appendix A).
        while True:
            a = gf.random_element()
            b = gf.random_element()
            if a > 0:
                yield EllipticCurve(gf, [a, b])
    if p % 3 == 2:
        # E with j-invariant 0 are singular.
        while True:
            b = gf.random_element()
            if b > 0:
                yield EllipticCurve(gf, [0, b])
    if p % 4 == 3:
        # E with j-invariant 1728 are singular.
        while True:
            a = gf.random_element()
            if a > 0:
                yield EllipticCurve(gf, [a, 0])
    D = 3
    while D % 4 != 3 or kronecker(-D, p) != -1:
        D = next_prime(D)

    yield from solve_cm(-D, q, c)
