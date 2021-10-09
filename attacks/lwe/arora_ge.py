from sage.all import GF


def attack(q, A, b, E, S=None):
    """
    Recovers the secret key s from the LWE samples A and b.
    More information: "The Learning with Errors Problem: Algorithms" (Section 1)
    :param q: the modulus
    :param A: the matrix A, represented as a list of lists
    :param b: the vector b, represented as a list
    :param E: the possible error values
    :param S: the possible values of the entries in s (default: None)
    :return: a list representing the secret key s
    """
    m = len(A)
    n = len(A[0])
    gf = GF(q)
    pr = gf[tuple(f"x{i}" for i in range(n))]
    gens = pr.gens()

    f = []
    for i in range(m):
        p = 1
        for e in E:
            p *= (b[i] - sum(A[i][j] * gens[j] for j in range(n)) - e)
        f.append(p)

    if S is not None:
        # Use information about the possible values for s to add more polynomials.
        for j in range(n):
            p = 1
            for s in S:
                p *= (gens[j] - s)
            f.append(p)

    s = []
    for p in pr.ideal(f).groebner_basis():
        assert p.nvariables() == 1 and p.degree() == 1
        s.append(int(-p.constant_coefficient()))

    return s
