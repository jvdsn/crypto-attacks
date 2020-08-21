import logging

from sage.all import Matrix
from sage.all import ZZ


def modular_bivariate(p, modulus, m, t, xbound, ybound):
    """
    Computes small modular roots of a bivariate polynomial.
    More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
    :param p: the polynomial
    :param modulus: the modulus
    :param m: the amount of normal shifts to use
    :param t: the amount of additional shifts to use
    :param xbound: an approximate bound on the x roots
    :param ybound: an approximate bound on the y roots
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    p = p.change_ring(ZZ)
    x, y = p.parent().gens()

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
    for k in range(m + 1):
        for j in range(1, t + 1):
            shift = y ** j * p ** k * modulus ** (m - k)
            shifts.add(shift)
            for monomial in shift.monomials():
                monomials.add(monomial)

    shifts = sorted(shifts)
    monomials = sorted(monomials)

    logging.debug(f"Filling the lattice ({len(shifts)} x {len(monomials)})...")
    lattice = Matrix(len(shifts), len(monomials))
    for row, shift in enumerate(shifts):
        for col, monomial in enumerate(monomials):
            lattice[row, col] = shift.monomial_coefficient(monomial) * monomial(xbound, ybound)

    logging.debug("Executing the LLL algorithm...")
    basis = lattice.LLL()

    logging.debug("Reconstructing polynomials...")
    new_polynomials = []
    for row in range(basis.nrows()):
        # Reconstruct the polynomial from reduced basis
        new_polynomial = 0
        for col, monomial in enumerate(monomials):
            new_polynomial += basis[row, col] * monomial // monomial(xbound, ybound)

        new_polynomials.append(new_polynomial)

    logging.debug("Generating resultants...")
    for p1 in new_polynomials:
        for p2 in new_polynomials:
            resultant = p1.resultant(p2, y)
            if not resultant.is_constant():
                for xroot, _ in resultant.univariate_polynomial().roots():
                    xroot = int(xroot)
                    p = p1.subs({x: xroot})
                    if not p.is_constant():
                        for yroot, _ in p.univariate_polynomial().roots():
                            yroot = int(yroot)
                            yield xroot, yroot
