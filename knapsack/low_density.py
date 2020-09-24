from math import ceil
from math import log2
from math import sqrt

from sage.all import Matrix
from sage.all import QQ


def attack(a, s, beta=0.5):
    """
    Tries to find e_i values such that sum(e_i * a_i) = s.
    This attack only works if the density of the a_i values is low enough
    :param a: the a_i values
    :param s: the s value
    :param beta: a parameter beta to tweak the lattice (default: 0.5)
    :return: the e_i values, or None if the e_i values were not found
    """
    n = len(a)
    d = n / log2(max(a))
    N = ceil(sqrt(beta * (1 - beta) * n))
    assert d < 0.9408, f"Density should be less than 0.9408 but was {d}."

    # Let's try all combinations of positive and negative, just to be sure.
    transformations = [
        lambda e: int(e + beta),
        lambda e: int(e - beta),
        lambda e: int(-e + beta),
        lambda e: int(-e - beta)
    ]

    lattice = Matrix(QQ, n + 1)
    for i in range(n):
        lattice[i, i] = 1
        lattice[i, n] = N * a[i]

    lattice[n] = [beta] * n + [N * s]

    basis = lattice.LLL()

    for i in range(n + 1):
        for transformation in transformations:
            s_ = 0
            es = []
            for j in range(n):
                e = transformation(basis[i, j])
                if 0 <= e <= 1:
                    s_ += e * a[j]
                    es.append(e)

            if s_ == s:
                return es
