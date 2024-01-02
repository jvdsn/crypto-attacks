import logging
from abc import ABCMeta
from abc import abstractmethod
from math import gcd

from sage.all import ZZ

from shared import small_roots


class Strategy(metaclass=ABCMeta):
    @abstractmethod
    def generate_S_M(self, f, m):
        """
        Generates the S and M sets.
        :param f: the polynomial
        :param m: the amount of normal shifts to use
        :return: a tuple containing the S and M sets
        """
        pass


class BasicStrategy(Strategy):
    def generate_S_M(self, f, m):
        S = set((f ** (m - 1)).monomials())
        M = set((f ** m).monomials())
        return S, M


class ExtendedStrategy(Strategy):
    def __init__(self, t):
        self.t = t

    def generate_S_M(self, f, m):
        x = f.parent().gens()
        assert len(x) == len(self.t)

        S = set()
        for monomial in (f ** (m - 1)).monomials():
            for xi, ti in zip(x, self.t):
                for j in range(ti + 1):
                    S.add(monomial * xi ** j)

        M = set()
        for monomial in S:
            M.update((monomial * f).monomials())

        return S, M


class Ernst1Strategy(Strategy):
    def __init__(self, t):
        self.t = t

    def generate_S_M(self, f, m):
        x1, x2, x3 = f.parent().gens()

        S = set()
        for i1 in range(m):
            for i2 in range(m - i1):
                for i3 in range(i2 + self.t + 1):
                    S.add(x1 ** i1 * x2 ** i2 * x3 ** i3)

        M = set()
        for i1 in range(m + 1):
            for i2 in range(m - i1 + 1):
                for i3 in range(i2 + self.t + 1):
                    M.add(x1 ** i1 * x2 ** i2 * x3 ** i3)

        return S, M


class Ernst2Strategy(Strategy):
    def __init__(self, t):
        self.t = t

    def generate_S_M(self, f, m):
        x1, x2, x3 = f.parent().gens()

        S = set()
        for i1 in range(m):
            for i2 in range(m - i1 + self.t):
                for i3 in range(m - i1):
                    S.add(x1 ** i1 * x2 ** i2 * x3 ** i3)

        M = set()
        for i1 in range(m + 1):
            for i2 in range(m - i1 + self.t + 1):
                for i3 in range(m - i1 + 1):
                    M.add(x1 ** i1 * x2 ** i2 * x3 ** i3)

        return S, M


def integer_multivariate(f, m, W, X, strategy, roots_method="resultants"):
    """
    Computes small integer roots of a multivariate polynomial.
    More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 2.2)
    :param f: the polynomial
    :param m: the parameter m
    :param W: the parameter W
    :param X: a list of approximate bounds on the roots for each variable
    :param strategy: the strategy to use (Appendix B)
    :param roots_method: the method to use to find roots (default: "resultants")
    :return: a generator generating small roots (tuples) of the polynomial
    """
    pr = f.parent()
    x = pr.gens()
    assert len(x) > 1

    S, M = strategy.generate_S_M(f, m)
    l = [0] * len(x)
    for monomial in S:
        for j, xj in enumerate(x):
            l[j] = max(l[j], monomial.degree(xj))

    a0 = int(f.constant_coefficient())
    assert a0 != 0
    while gcd(a0, W) != 1:
        W += 1

    R = W
    for j, Xj in enumerate(X):
        while gcd(a0, Xj) != 1:
            Xj += 1

        R *= Xj ** l[j]
        X[j] = Xj

    assert gcd(a0, R) == 1
    f_ = (pow(a0, -1, R) * f % R).change_ring(ZZ)

    logging.debug("Generating shifts...")

    shifts = []
    monomials = set()
    for monomial in S:
        g = monomial * f_
        for xj, Xj, lj in zip(x, X, l):
            g *= Xj ** (lj - monomial.degree(xj))

        shifts.append(g)
        monomials.add(monomial)

    for monomial in M:
        if monomial not in S:
            shifts.append(monomial * R)
            monomials.add(monomial)

    L, monomials = small_roots.create_lattice(pr, shifts, X)
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, R, monomials, X)
    for roots in small_roots.find_roots(pr, [f] + polynomials, method=roots_method):
        yield tuple(roots[xi] for xi in x)
