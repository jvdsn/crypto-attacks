import logging
from random import choice
from random import randrange

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import cyclotomic_polynomial
from sage.all import factor
from sage.all import is_prime
from sage.all import kronecker
from sage.all import next_prime
from sage.all import pari

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
    :param D: the (negative) CM discriminant to use (default: randomly chosen from [-11, -19, -43, -67, -163])
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random anomalous elliptic curves
    """
    # Idea:
    # 4q = t^2 - Dv^2
    # Dv^2 = t^2 - 4q
    # -> if D divides 1 - 4q and the result is square, it is a good D value
    Ds = [-11, -19, -43, -67, -163] if D is None else [D]
    Ds = [D for D in Ds if (1 - 4 * q) % D == 0 and is_square((1 - 4 * q) // D)]
    assert len(Ds) > 0, "Invalid value for q and default values of D."
    D = choice(Ds)
    logging.info(f"Found appropriate D value = {D}")
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
        # Idea:
        # 4q = t^2 - Dv^2
        # 4q = 1 - D(2m + 1)^2
        # 4q = 1 - D(4m^2 + 4m + 1)
        # q = -Dm^2 - Dm - (D + 1) / 4
        D = choice(Ds)
        m_bit_length = (q_bit_length - D.bit_length()) // 2 + 1
        m = randrange(2 ** (m_bit_length - 1), 2 ** m_bit_length)
        q = -D * m * (m + 1) + (-D + 1) // 4
        if q.bit_length() == q_bit_length and is_prime(q):
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
    assert t ** 2 < 4 * q, f"Trace {t} is outside Hasse's interval for GF({q})"

    # Idea:
    # 4q = t^2 - Dv^2
    # Dv^2 = t^2 - 4q
    # -> D can be immediately computed from t and q
    if D is None:
        D = t ** 2 - 4 * q
        # We don't make D square-free because that removes solutions.
        logging.info(f"Found appropriate D value = {D}")
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
        # Idea:
        # 4q = t^2 - Dv^2
        # -> we simply try random values for v until a suitable q is found
        v = randrange(2 ** (v_bit_length - 1), 2 ** v_bit_length)
        q4 = t ** 2 - D * v ** 2
        if q4.bit_length() - 2 == q_bit_length and q4 % 4 == 0 and is_prime(q4 // 4):
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
    factor_4m = factor(4 * m)

    def get_q(D):
        # We can't use qfbcornacchia here, because it does not return all (or any) solutions...
        for t in set(map(lambda sol: int(sol[0]), pari.qfbsolve(pari.Qfb(1, 0, -D), factor_4m, 1))):
            if is_prime(m + 1 - t):
                return m + 1 - t
            if is_prime(m + 1 + t):
                return m + 1 + t

    q = None
    if D is None:
        for D in range(7, 4 * m):
            if not (D % 4 == 0 or D % 4 == 3):
                continue

            q = get_q(-D)
            if q is not None:
                break

        assert q is not None, "Unable to find appropriate D value for m."
        D = int(-D)
        logging.info(f"Found appropriate D value = {D}")
    else:
        q = get_q(D)
        assert q is not None, "Invalid values for m and D."

    yield from generate_with_trace_q(q + 1 - m, q, D, c)


def generate_supersingular(q, c=None):
    """
    Generates random supersingular elliptic curves.
    More information: Broeker R., "Constructing Supersingular Elliptic Curves"
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


def generate_mnt(k, h_min=1, h_max=4, D_min=7, D_max=10000, c=None):
    """
    Generates random MNT curves.
    More information: Scott M., Barreto P. S. L. M., "Generating more MNT elliptic curves"
    :param k: the embedding degree (3, 4, or 6)
    :param h_min: the minimum cofactor to try (inclusive, default: 1)
    :param h_max: the maximum cofactor to try (inclusive, default: 4)
    :param D_min: the minimum D value to try (inclusive, default: 7)
    :param D_max: the maximum D value to try (inclusive, default: 10000)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random MNT curves with embedding degree k
    """
    assert k in {3, 4, 6}

    phi = cyclotomic_polynomial(k)
    l = -2 * (k // 2) + 4
    for h in range(h_min, h_max + 1):
        for d in range(1, 4 * h):
            if k == 4 and not (d % 4 == 1 or d % 4 == 2):
                continue
            if (k == 3 or k == 6) and not (d % 6 == 1 or d % 6 == 3):
                continue

            a = l * h + d
            b = 4 * h - d
            f = a ** 2 - b ** 2
            factor_f = 0 if f == 0 else factor(f)
            for D in range(D_min, D_max + 1):
                if not (D % 4 == 0 or D % 4 == 3):
                    continue

                g = d * b * D
                if is_square(g):
                    continue

                ys = set(map(lambda sol: int(sol[0]), pari.qfbsolve(pari.Qfb(1, 0, -g), factor_f, 1)))
                for y in ys:
                    if (y - a) % b != 0:
                        continue
                    x = (y - a) // b
                    if phi(x) % d != 0:
                        continue
                    r = int(phi(x) // d)
                    n = h * r
                    q = n + x
                    # Unfortunately, this sanity check is needed in some cases.
                    if all((q ** i - 1) % r == 0 for i in range(1, k)):
                        continue
                    if is_prime(r) and is_prime(q):
                        logging.info(f"Found appropriate D value = {-D}")
                        yield from generate_with_order_q(n, q, -D, c)


def generate_mnt_k2(q_bit_length, D=None, c=None):
    """
    Generates random MNT curves with embedding degree 2.
    More information: Scott M., Barreto P. S. L. M., "Generating more MNT elliptic curves" (Section 5)
    :param q_bit_length: the bit length of the modulus, used to generate a random q
    :param D: the (negative) CM discriminant to use (default: -7)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random MNT curves with embedding degree k
    """
    if D is None:
        D = -7
        logging.info(f"Found appropriate D value = {D}")
    else:
        assert D < 0 and (D % 4 == 0 or D % 4 == 1), "Invalid value for D."

    x_bit_length = (q_bit_length + 2) // 2
    z_bit_length = (x_bit_length - 1 - D.bit_length()) // 2 + 1
    assert z_bit_length > 0, "Invalid values for D and q bit length."
    while True:
        z = randrange(2 ** (z_bit_length - 1), 2 ** z_bit_length)
        x = 2 * (-D) * z ** 2 + 1
        q = (x ** 2 + 4 * x - 1) // 4
        r = (x + 1) // 2
        if q.bit_length() == q_bit_length and is_prime(r) and is_prime(q):
            yield from generate_with_trace_q(x + 1, q, D, c)
