def dlog(A, B):
    """
    Computes l such that A^l = B, in GF(p).
    :param A: the matrix A
    :param B: the matrix B
    :return: l, or None if l could not be found
    """
    assert A.is_square() and B.is_square() and A.nrows() == B.nrows()

    # TODO: extend to GF(p^k) if necessary?
    J, P = A.jordan_form(transformation=True)
    B = P ** -1 * B * P
    r = 0
    for s1, s2 in zip(*J.subdivisions()):
        S = J.subdivision(s1, s2)
        assert S.is_square()

        n = S.nrows()
        r += n
        if n >= 2:
            B1 = B[r - 1, r - 1]
            B2 = B[r - 2, r - 1]
            l = (S[n - 1, n - 1] * B2) / B1
            return int(l)

    return None


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
