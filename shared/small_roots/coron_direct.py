import logging

from sage.all import ZZ
from sage.all import matrix

from shared import small_roots
from shared.polynomial import max_norm


def integer_bivariate(p, k, X, Y, echelon_algorithm="default", roots_method="groebner"):
    """
    Computes small integer roots of a bivariate polynomial.
    More information: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach"
    :param p: the polynomial
    :param k: the amount of shifts to use
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param echelon_algorithm: the algorithm to use to calculate the Echelon form of L (default: "default")
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    pr = p.parent()
    x, y = pr.gens()
    delta = max(p.degrees())

    (i0, j0), W = max_norm(p(x * X, y * Y))

    logging.debug("Calculating n...")
    S = matrix(ZZ, k ** 2, k ** 2)
    for a in range(k):
        for b in range(k):
            s = x ** a * y ** b * p
            for i in range(k):
                for j in range(k):
                    S[a * k + b, i * k + j] = s.coefficient([i0 + i, j0 + j])

    n = abs(S.det())
    logging.debug(f"Found {n = }")

    # Monomials are collected in "left" and "right" lists, which determine where the columns are in relation to each other.
    # This partition ensures the Echelon form will set desired monomial coefficients to zero.
    logging.debug("Generating monomials...")
    left_monomials = []
    right_monomials = []
    for i in range(k + delta):
        for j in range(k + delta):
            if 0 <= i - i0 < k and 0 <= j - j0 < k:
                left_monomials.append(x ** i * y ** j)
            else:
                right_monomials.append(x ** i * y ** j)

    assert len(left_monomials) == k ** 2
    monomials = left_monomials + right_monomials

    logging.debug("Generating shifts...")

    shifts = []
    for a in range(k):
        for b in range(k):
            s = x ** a * y ** b * p
            shifts.append(s)

    for monomial in monomials:
        r = monomial * n
        shifts.append(r)

    logging.debug(f"Filling the lattice ({len(shifts)} x {len(monomials)})...")
    L = matrix(ZZ, len(shifts), len(monomials))
    for row, shift in enumerate(shifts):
        for col, monomial in enumerate(monomials):
            L[row, col] = shift.monomial_coefficient(monomial) * monomial(X, Y)

    logging.debug("Generating Echelon form...")
    L = L.echelon_form(algorithm=echelon_algorithm)

    L2 = L.submatrix(k ** 2, k ** 2, (k + delta) ** 2 - k ** 2)
    L2 = small_roots.reduce_lattice(L2)
    # Only use right monomials now (corresponding the the sublattice).
    polynomials = small_roots.reconstruct_polynomials(L2, p, n, right_monomials, [X, Y])
    for roots in small_roots.find_roots(pr, [p] + polynomials, method=roots_method):
        yield roots[x], roots[y]
