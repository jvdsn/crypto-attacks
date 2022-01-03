import logging

from sage.all import GF
from sage.all import identity_matrix
from sage.matrix.matrix2 import _jordan_form_vector_in_difference


def find_eigenvalues(A):
    """
    Computes the eigenvalues and P matrices for a specific matrix A.
    :param A: the matrix A.
    :return: a generator generating tuples of
        K: the extension field of the eigenvalue,
        k: the degree of the factor of the charpoly associated with the eigenvalue,
        e: the multiplicity of the factor of the charpoly associated with the eigenvalue,
        l: the eigenvalue,
        P: the transformation matrix P (only the first e columns are filled)
    """
    factors = {}
    for g, e in A.charpoly().factor():
        k = g.degree()
        if k not in factors or e > factors[k][0]:
            factors[k] = (e, g)

    p = A.base_ring().order()
    for k, (e, g) in factors.items():
        logging.debug(f"Found factor {g} with degree {k} and multiplicity {e}")
        K = GF(p ** k, "x", modulus=g, impl="modn" if k == 1 else "pari")
        l = K.gen()
        # Assuming there is only 1 Jordan block for this eigenvalue.
        Vlarge = ((A - l) ** e).right_kernel().basis()
        Vsmall = ((A - l) ** (e - 1)).right_kernel().basis()
        v = _jordan_form_vector_in_difference(Vlarge, Vsmall)
        P = identity_matrix(K, A.nrows())
        for i in reversed(range(e)):
            P.set_row(i, v)
            v = (A - l) * v

        P = P.transpose()
        yield K, k, e, l, P


def dlog(A, B):
    """
    Computes l such that A^l = B.
    :param A: the matrix A
    :param B: the matrix B
    :return: a generator generating values for l and m, where A^l = B mod m.
    """
    assert A.is_square() and B.is_square() and A.nrows() == B.nrows()

    p = A.base_ring().order()
    for K, k, e, l, P in find_eigenvalues(A):
        B_ = P ** -1 * B * P
        logging.debug(f"Computing dlog in {K}...")
        yield int(B_[0, 0].log(l)), int(p ** k - 1)
        if e >= 2:
            B1 = B_[e - 1, e - 1]
            B2 = B_[e - 2, e - 1]
            yield int((l * B2) / B1), int(p ** k)


def dlog_equation(A, x, y):
    """
    Computes l such that A^l * x = y, in GF(p).
    :param A: the matrix A
    :param x: the vector x
    :param y: the vector y
    :return: l, or None if l could not be found
    """
    assert A.is_square()

    # TODO: extend to GF(p^k) if necessary?
    J, P = A.jordan_form(transformation=True)
    x = P ** -1 * x
    y = P ** -1 * y
    r = 0
    for s1, s2 in zip(*J.subdivisions()):
        S = J.subdivision(s1, s2)
        assert S.is_square()

        n = S.nrows()
        r += n
        if n >= 2:
            x1 = x[r - 1]
            x2 = x[r]
            y1 = y[r - 1]
            y2 = y[r]
            l = S[n - 1, n - 1] * (y1 - x1 * y2 / x2) / y2
            return int(l)

    return None
