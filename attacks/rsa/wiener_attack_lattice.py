import logging
import os
import sys
from itertools import combinations
from math import isqrt
from math import prod

from sage.all import RR
from sage.all import ZZ
from sage.all import matrix

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi
from shared.lattice import shortest_vectors
from shared.small_roots import aono
from shared.small_roots import reduce_lattice


def attack(N, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    More information: Nguyen P. Q., "Public-Key Cryptanalysis"
    :param N: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors and the private exponent, or None if the private exponent was not found
    """
    s = isqrt(N)
    L = matrix(ZZ, [[e, s], [N, 0]])

    for v in shortest_vectors(L):
        d = v[1] // s
        k = abs(v[0] - e * d) // N
        d = abs(d)
        if pow(pow(2, e, N), d, N) != 2:
            continue

        phi = (e * d - 1) // k
        factors = known_phi.factorize(N, phi)
        if factors:
            return *factors, int(d)


# Construct R_{u, v} for a specific monomial.
def _construct_relation(N, monomial, x):
    vars = monomial.variables()
    l = [x[i] for i in range(x.index(vars[-1]) + 1)]
    R = 1
    u = 0
    v = 0
    i = len(vars)
    for var in vars:
        if var != x[0] and var < l[0] and len(l) >= 2 * i:
            # Guo equation
            R *= l[0] - var
            l.pop(0)
            v += 1
        else:
            # Wiener equation
            R *= var - N
            u += 1

        l.remove(var)
        i -= 1

    return R, u, v


def attack_multiple_exponents_1(N, e, alpha):
    """
    Recovers the prime factors of a modulus given multiple public exponents with small corresponding private exponents.
    More information: Howgrave-Graham N., Seifert J., "Extending Wiener’s Attack in the Presence of Many Decrypting Exponents"
    :param N: the modulus
    :param e: the public exponent
    :param alpha: the bound on the private exponents (i.e. d < N^alpha)
    :return: a tuple containing the prime factors, or None if the prime factors were not found
    """
    n = len(e)
    pr = ZZ[",".join(f"x{i}" for i in range(n))]
    x = pr.gens()

    monomials = [1]
    for i, xi in enumerate(x):
        monomials.append(xi)
        for j in range(i):
            for comb in combinations(x[:i], j + 1):
                monomials.append(prod(comb) * xi)

    L = matrix(ZZ, len(monomials))
    exp_a = [n]
    exp_b = [0]
    for col, monomial in enumerate(monomials):
        if col == 0:
            L[0, 0] = 1
            continue

        R, u, v = _construct_relation(N, monomial, x)
        for row, monomial in enumerate(monomials):
            if row == 0:
                L[0, col] = R.constant_coefficient()
            else:
                L[row, col] = R.monomial_coefficient(monomial) * monomial(*e)

        exp_a.append(n - v)
        exp_b.append(u / 2)

    max_a = max(exp_a)
    max_b = max(exp_b)
    D = matrix(ZZ, len(monomials))
    for i, (a, b) in enumerate(zip(exp_a, exp_b)):
        D[i, i] = int(RR(N) ** ((max_a - a) * alpha + (max_b - b)))

    L = L * D
    L_ = reduce_lattice(L)
    b = L.solve_left(L_[0])
    phi = round(b[1] / b[0] * e[0])
    factors = known_phi.factorize(N, phi)
    if factors:
        return factors


def attack_multiple_exponents_2(N, e, d_bit_length, m=1):
    """
    Recovers the prime factors of a modulus given multiple public exponents with small corresponding private exponents.
    More information: Aono Y., "Minkowski sum based lattice construction for multivariate simultaneous Coppersmith’s technique and applications to RSA" (Section 4)
    :param N: the modulus
    :param e: the public exponent
    :param d_bit_length: the bit length of the private exponents
    :param m: the m value to use for the small roots method (default: 1)
    :return: a tuple containing the prime factors, or None if the prime factors were not found
    """
    l = len(e)
    assert len(set(e)) == l, "All public exponents must be distinct"
    assert l >= 1, "At least one public exponent is required."

    pr = ZZ[",".join(f"x{i}" for i in range(l)) + ",y"]
    gens = pr.gens()
    x = gens[:-1]
    y = gens[-1]
    F = [-1 + x[k] * (y + N) for k in range(l)]
    X = [2 ** d_bit_length for _ in range(l)]
    Y = 3 * isqrt(N)
    logging.info(f"Trying m = {m}...")
    for roots in aono.integer_multivariate(F, e, m, X + [Y]):
        phi = roots[y] + N
        factors = known_phi.factorize(N, phi)
        if factors:
            return factors
