import logging

from sage.all import ZZ

from shared import small_roots


def modular_bivariate(f, e, m, t, X, Y, roots_method="groebner"):
    """
    Computes small modular roots of a bivariate polynomial.
    More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
    :param f: the polynomial
    :param e: the modulus
    :param m: the amount of normal shifts to use
    :param t: the amount of additional shifts to use
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    f = f.change_ring(ZZ)
    pr = f.parent()
    x, y = pr.gens()

    logging.debug("Generating shifts...")

    shifts = []
    for k in range(m + 1):
        for i in range(m - k + 1):
            g = x ** i * f ** k * e ** (m - k)
            shifts.append(g)

        for j in range(t + 1):
            h = y ** j * f ** k * e ** (m - k)
            shifts.append(h)

    L, monomials = small_roots.create_lattice(pr, shifts, [X, Y])
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, e ** m, monomials, [X, Y])
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield roots[x], roots[y]
