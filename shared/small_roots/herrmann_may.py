import logging

from sage.all import ZZ

from shared import small_roots


def modular_bivariate(f, e, m, t, X, Y, roots_method="groebner"):
    """
    Computes small modular roots of a bivariate polynomial.
    More information: Herrmann M., May A., "Maximizing Small Root Bounds by Linearization and Applications to Small Secret Exponent RSA"
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

    pr = ZZ["u, x, y"]
    u, x, y = pr.gens()
    qr = pr.quotient(1 + x * y - u)
    U = X * Y

    logging.debug("Generating shifts...")

    shifts = set()
    monomials = set()
    for k in range(m + 1):
        for i in range(m - k + 1):
            g = x ** i * f ** k * e ** (m - k)
            g = qr(g).lift()
            shifts.add(g)
            monomials.update(g.monomials())

    for j in range(1, t + 1):
        for k in range(m // t * j, m + 1):
            h = y ** j * f ** k * e ** (m - k)
            h = qr(h).lift()
            shifts.add(h)
            monomials.add(u ** k * y ** j)

    L = small_roots.fill_lattice(shifts, monomials, [U, X, Y])
    L = small_roots.reduce(L)
    polynomials = small_roots.reconstruct_polynomials(L, monomials, [U, X, Y])

    pr = f.parent()
    x, y = pr.gens()
    for i, polynomial in enumerate(polynomials):
        polynomials[i] = polynomial(1 + x * y, x, y)

    for roots in small_roots.find_roots(f, polynomials, pr, method=roots_method):
        yield roots[x], roots[y]
