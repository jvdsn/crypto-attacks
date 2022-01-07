import logging

from shared import small_roots


def modular_bivariate(f, e, M, m, t, Y, Z, roots_method="groebner"):
    """
    Computes small modular roots of a bivariate polynomial.
    More information: Blomer J., May A., "New Partial Key Exposure Attacks on RSA" (Section 6)
    :param f: the polynomial
    :param e: the parameter e
    :param M: the parameter M
    :param m: the parameter m
    :param t: the parameter t
    :param Y: an approximate bound on the y roots
    :param Z: an approximate bound on the z roots
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of y and z roots) of the polynomial
    """
    pr = f.parent()
    y, z = pr.gens()

    logging.debug("Generating shifts...")

    shifts = []
    monomials = set()
    for i in range(m + 1):
        for j in range(i + 1):
            g = y ** j * (e * M) ** i * f ** (m - i)
            shifts.append(g)
            monomials.update(g.monomials())

        for j in range(1, t + 1):
            h = z ** j * (e * M) ** i * f ** (m - i)
            shifts.append(h)
            monomials.update(h.monomials())

    L = small_roots.fill_lattice(shifts, monomials, [Y, Z])
    L = small_roots.reduce(L)
    polynomials = small_roots.reconstruct_polynomials(L, monomials, [Y, Z])
    for roots in small_roots.find_roots(f, polynomials, pr, method=roots_method):
        yield roots[y], roots[z]
