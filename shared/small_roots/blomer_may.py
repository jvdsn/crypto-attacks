import logging

from sage.all import ZZ

from shared import small_roots


def modular_trivariate(f, N, m, t, X, Y, Z, roots_method="groebner"):
    """
    Computes small modular roots of a trivariate polynomial.
    More information: Blomer J., May A., "New Partial Key Exposure Attacks on RSA" (Section 4)
    :param f: the polynomial
    :param N: the modulus
    :param m: the parameter m
    :param t: the parameter t
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param Z: an approximate bound on the z roots
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of x, y, and z roots) of the polynomial
    """
    f = f.change_ring(ZZ)
    pr = f.parent()
    x, y, z = pr.gens()

    logging.debug("Generating shifts...")

    shifts = []
    for i in range(m + 1):
        for j in range(i + 1):
            for k in range(j + 1):
                g = x ** (j - k) * z ** k * N ** i * f ** (m - i)
                shifts.append(g)

            for k in range(1, t + 1):
                h = x ** j * y ** k * N ** i * f ** (m - i)
                shifts.append(h)

    L, monomials = small_roots.create_lattice(pr, shifts, [X, Y, Z])
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, N ** m, monomials, [X, Y, Z])
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield roots[x], roots[y], roots[z]


def modular_bivariate(f, eM, m, t, Y, Z, roots_method="groebner"):
    """
    Computes small modular roots of a bivariate polynomial.
    More information: Blomer J., May A., "New Partial Key Exposure Attacks on RSA" (Section 6)
    :param f: the polynomial
    :param eM: the modulus
    :param m: the parameter m
    :param t: the parameter t
    :param Y: an approximate bound on the y roots
    :param Z: an approximate bound on the z roots
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of y and z roots) of the polynomial
    """
    f = f.change_ring(ZZ)
    pr = f.parent()
    y, z = pr.gens()

    logging.debug("Generating shifts...")

    shifts = []
    for i in range(m + 1):
        for j in range(i + 1):
            g = y ** j * eM ** i * f ** (m - i)
            shifts.append(g)

        for j in range(1, t + 1):
            h = z ** j * eM ** i * f ** (m - i)
            shifts.append(h)

    L, monomials = small_roots.create_lattice(pr, shifts, [Y, Z])
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, eM ** m, monomials, [Y, Z])
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield roots[y], roots[z]
