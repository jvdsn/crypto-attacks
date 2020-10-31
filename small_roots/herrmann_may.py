import logging

from sage.all import Matrix
from sage.all import ZZ


def modular_bivariate(p, modulus, m, t, xbound, ybound, early_return=True):
    """
    Computes small modular roots of a bivariate polynomial.
    More information: Herrmann M., May A., "Maximizing Small Root Bounds by Linearization and Applications to Small Secret Exponent RSA"
    :param p: the polynomial
    :param modulus: the modulus
    :param m: the amount of normal shifts to use
    :param t: the amount of additional shifts to use
    :param xbound: an approximate bound on the x roots
    :param ybound: an approximate bound on the y roots
    :param early_return: try to return as early as possible (default: true)
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    pr = ZZ["u, x, y"]
    u, x, y = pr.gens()
    qr = pr.quotient(x * y + 1 - u)
    p = qr(p).lift()
    ubound = xbound * ybound

    shifts = set()
    monomials = set()
    logging.debug("Generating x shifts...")
    for k in range(m + 1):
        for i in range(m - k + 1):
            shift = x ** i * p ** k * modulus ** (m - k)
            shifts.add(shift)
            for monomial in shift.monomials():
                monomials.add(monomial)

    logging.debug("Generating y shifts...")
    for j in range(1, t + 1):
        for k in range(m // t * j, m + 1):
            shift = y ** j * p ** k * modulus ** (m - k)
            shift = qr(shift).lift()
            shifts.add(shift)
            monomial = u ** k * y ** j
            monomials.add(monomial)

    shifts = sorted(shifts)
    monomials = sorted(monomials)

    logging.debug(f"Filling the lattice ({len(shifts)} x {len(monomials)})...")
    lattice = Matrix(len(shifts), len(monomials))
    for row, shift in enumerate(shifts):
        for col, monomial in enumerate(monomials):
            lattice[row, col] = shift.monomial_coefficient(monomial) * monomial(ubound, xbound, ybound)

    logging.debug("Executing the LLL algorithm...")
    basis = lattice.LLL()

    logging.debug("Reconstructing polynomials...")
    v, w = ZZ["v, w"].gens()
    new_polynomials = []
    for row in range(basis.nrows()):
        # Reconstruct the polynomial from reduced basis
        new_polynomial = 0
        for col, monomial in enumerate(monomials):
            new_polynomial += basis[row, col] * monomial(v * w + 1, v, w) // monomial(ubound, xbound, ybound)

        new_polynomials.append(new_polynomial)

    logging.debug("Generating resultants...")
    for p1 in new_polynomials:
        for p2 in new_polynomials:
            resultant = p1.resultant(p2, w)
            if not resultant.is_constant():
                for vroot, _ in resultant.univariate_polynomial().roots():
                    vroot = int(vroot)
                    p = p1.subs({v: vroot})
                    if not p.is_constant():
                        for wroot, _ in p.univariate_polynomial().roots():
                            wroot = int(wroot)
                            yield vroot, wroot

                        if early_return:
                            return
