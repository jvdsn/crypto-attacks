import logging

from sage.all import RR
from sage.all import ZZ
from sage.all import gcd

from shared import small_roots


def integer_trivariate_1(f, m, t, W, X, Y, Z, check_bounds=True, roots_method="groebner"):
    """
    Computes small integer roots of a trivariate polynomial.
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents" (Section 4.1.1)
    :param f: the polynomial
    :param m: the parameter m
    :param t: the parameter t
    :param W: the parameter W
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param Z: an approximate bound on the z roots
    :param check_bounds: whether or not we should check bounds (default: True)
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    pr = f.parent()
    x, y, z = pr.gens()

    tau = t / m
    if check_bounds and RR(X) ** (1 + 3 * tau) * RR(Y) ** (2 + 3 * tau) * RR(Z) ** (1 + 3 * tau + 3 * tau ** 2) > RR(W) ** (1 + 3 * tau):
        logging.debug(f"Bound check failed for m = {m}, t = {t}")
        return

    R = f.constant_coefficient()
    assert R != 0
    while gcd(R, X) != 1:
        X += 1
    while gcd(R, Y) != 1:
        Y += 1
    while gcd(R, Z) != 1:
        Z += 1
    while gcd(R, W) != 1:
        W += 1

    n = (X * Y) ** m * Z ** (m + t) * W
    assert gcd(R, n) == 1
    f_ = (pow(R, -1, n) * f % n).change_ring(ZZ)

    logging.debug("Generating shifts...")

    shifts = set()
    monomials = set()
    for i in range(m + 1):
        for j in range(m - i + 1):
            for k in range(j + 1):
                g = x ** i * y ** j * z ** k * f_ * X ** (m - i) * Y ** (m - j) * Z ** (m + t - k)
                shifts.add(g)
                monomials.update(g.monomials())

            for k in range(j + 1, j + t + 1):
                h = x ** i * y ** j * z ** k * f_ * X ** (m - i) * Y ** (m - j) * Z ** (m + t - k)
                shifts.add(h)
                monomials.update(h.monomials())

    for i in range(m + 2):
        j = m + 1 - i
        for k in range(j + 1):
            g_ = n * x ** i * y ** j * z ** k
            shifts.add(g_)
            monomials.update(g_.monomials())

        for k in range(j + 1, j + t + 1):
            h_ = n * x ** i * y ** j * z ** k
            shifts.add(h_)
            monomials.update(h_.monomials())

    L = small_roots.fill_lattice(shifts, monomials, [X, Y, Z])
    L = small_roots.reduce(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, monomials, [X, Y, Z])
    for roots in small_roots.find_roots([f] + polynomials, pr, method=roots_method):
        yield roots[x], roots[y], roots[z]


def integer_trivariate_2(f, m, t, W, X, Y, Z, check_bounds=True, roots_method="groebner"):
    """
    Computes small integer roots of a trivariate polynomial.
    More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents" (Section 4.1.2)
    :param f: the polynomial
    :param m: the parameter m
    :param t: the parameter t
    :param W: the parameter W
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param Z: an approximate bound on the z roots
    :param check_bounds: whether or not we should check bounds (default: True)
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    pr = f.parent()
    x, y, z = pr.gens()

    tau = t / m
    if check_bounds and RR(X) ** (2 + 3 * tau) * RR(Y) ** (3 + 6 * tau + 3 * tau ** 2) * RR(Z) ** (3 + 3 * tau) > RR(W) ** (2 + 3 * tau):
        logging.debug(f"Bound check failed for m = {m}, t = {t}")
        return

    R = f.constant_coefficient()
    assert R != 0
    while gcd(R, X) != 1:
        X += 1
    while gcd(R, Y) != 1:
        Y += 1
    while gcd(R, Z) != 1:
        Z += 1
    while gcd(R, W) != 1:
        W += 1

    n = X ** m * Y ** (m + t) * Z ** m * W
    assert gcd(R, n) == 1
    f_ = (pow(R, -1, n) * f % n).change_ring(ZZ)

    logging.debug("Generating shifts...")

    shifts = set()
    monomials = set()
    for i in range(m + 1):
        for j in range(m - i + 1):
            for k in range(m - i + 1):
                g = x ** i * y ** j * z ** k * f_ * X ** (m - i) * Y ** (m + t - j) * Z ** (m - k)
                shifts.add(g)
                monomials.update(g.monomials())

        for j in range(m - i + 1, m - i + t + 1):
            for k in range(m - i + 1):
                h = x ** i * y ** j * z ** k * f_ * X ** (m - i) * Y ** (m + t - j) * Z ** (m - k)
                shifts.add(h)
                monomials.update(h.monomials())

    for i in range(m + 2):
        for j in range(m + t + 2 - i):
            k = m + 1 - i
            g_ = n * x ** i * y ** j * z ** k
            shifts.add(g_)
            monomials.update(g_.monomials())

    for i in range(m + 1):
        j = m + t + 1 - i
        for k in range(m - i + 1):
            h_ = n * x ** i * y ** j * z ** k
            shifts.add(h_)
            monomials.update(h_.monomials())

    L = small_roots.fill_lattice(shifts, monomials, [X, Y, Z])
    L = small_roots.reduce(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, monomials, [X, Y, Z])
    for roots in small_roots.find_roots([f] + polynomials, pr, method=roots_method):
        yield roots[x], roots[y], roots[z]
