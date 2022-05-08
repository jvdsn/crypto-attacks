import os
import sys

from sage.all import QQ
from sage.all import ZZ
from sage.all import block_matrix
from sage.all import identity_matrix
from sage.all import matrix
from sage.all import vector

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.lattice import closest_vectors


def attack(x_, N, pi, nu, a, p, u, b, delta=None):
    """
    Solves the extended hidden number problem (definition 6 in the source paper).
    More information: Hlavac M., Rosa T., "Extended Hidden Number Problem and Its Cryptanalytic Applications" (Section 4)
    :param x_: the known bits of x
    :param N: the modulus
    :param pi: the pi values
    :param nu: the nu values
    :param a: the alpha values
    :param p: the rho values
    :param u: the mu values
    :param b: the beta values
    :param delta: the delta value (default: automatically computed)
    :return: a generator generating possible values of x
    """
    assert len(pi) == len(nu), "pi and v lists should be of equal length."
    assert len(a) == len(p) == len(u) == len(b), "a, p, u, and b lists should be of equal length."

    m = len(pi)
    d = len(a)
    l = []
    for i in range(d):
        assert len(p[i]) == len(u[i]), "p[i] and u[i] lists should be of equal length."
        l.append(len(p[i]))

    L = sum(l)
    D = d + m + L
    KD = QQ(2 ** (D / 4) * (m + L) ** (1 / 2) + 1) / 2
    delta = QQ(1 / (2 * KD)) if delta is None else QQ(delta)
    assert 0 < KD * delta < 1

    Id = identity_matrix(ZZ, d)
    P = matrix(ZZ, L, d)
    row = 0
    for i in range(d):
        for j in range(l[i]):
            P[row, i] = p[i][j]
            row += 1

    A = matrix(ZZ, m, d)
    for i in range(d):
        for j in range(m):
            A[j, i] = a[i] * 2 ** pi[j]

    X = matrix(QQ, m, m)
    for j in range(m):
        X[j, j] = delta / (2 ** nu[j])

    K = matrix(QQ, L, L)
    pos = 0
    for i in range(d):
        for j in range(l[i]):
            K[pos, pos] = delta / (2 ** u[i][j])
            pos += 1

    B = block_matrix(QQ, [
        [N * Id, matrix(QQ, d, m), matrix(QQ, d, L)],
        [A, X, matrix(QQ, m, L)],
        [P, matrix(QQ, L, m), K]
    ])

    v = vector(QQ, [delta / 2] * D)
    for i in range(d):
        v[i] = (b[i] - a[i] * x_) % N

    for W in closest_vectors(B, v, algorithm="babai"):
        z = x_
        for j in range(m):
            z += 2 ** pi[j] * int((W[d + j] * 2 ** nu[j]) / delta)
            z %= N

        yield z


def dsa_known_bits(N, h, r, s, x, k):
    """
    Recovers the (EC)DSA private key if any nonce bits are known.
    :param N: the modulus
    :param h: a list containing the hashed messages
    :param r: a list containing the r values
    :param s: a list containing the s values
    :param x: the partial private key (PartialInteger, can be fully unknown)
    :param k: a list containing the partial nonces (PartialIntegers)
    :return: a generator generating possible private keys
    """
    assert len(h) == len(r) == len(s) == len(k), "h, r, s, and k lists should be of equal length."
    x_, pi, nu = x.get_known_and_unknowns()
    a = []
    p = []
    u = []
    b = []
    for hi, ri, si, ki in zip(h, r, s, k):
        a.append(ri)
        ki_, li, ui = ki.get_known_and_unknowns()
        p.append([(-si * 2 ** lij) % N for lij in li])
        u.append(ui)
        b.append((si * ki_ - hi) % N)

    yield from attack(x_, N, pi, nu, a, p, u, b)
