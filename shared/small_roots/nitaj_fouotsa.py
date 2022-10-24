import logging

from sage.all import ZZ

from shared import small_roots


def modular_trivariate(f, e, m, t, X, Y, Z, roots_method="groebner"):
    """
    Computes small modular roots of a trivariate polynomial.
    More information: Nitaj A., Fouotsa E., "A New Attack on RSA and Demytko's Elliptic Curve Cryptosystem" (Section 3)
    :param f: the polynomial
    :param e: the modulus
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
    for k in range(m + 1):
        for i1 in range(k, m + 1):
            i2 = k
            i3 = m - i1
            g = x ** (i1 - k) * z ** i3 * f ** k * e ** (m - k)
            shifts.append(g)

        i1 = k
        for i2 in range(k + 1, i1 + t + 1):
            i3 = m - i1
            h = y ** (i2 - k) * z ** i3 * f ** k * e ** (m - k)
            shifts.append(h)

    L, monomials = small_roots.create_lattice(pr, shifts, [X, Y, Z])
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, e ** m, monomials, [X, Y, Z])
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield roots[x], roots[y], roots[z]
