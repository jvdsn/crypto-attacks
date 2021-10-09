import os
import sys

from sage.all import QQ
from sage.all import ZZ
from sage.all import matrix
from sage.all import vector

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.lattice import shortest_vectors


def attack(a, b, m, X):
    """
    Solves the hidden number problem using an attack based on the shortest vector problem.
    The hidden number problem is defined as finding y such that {xi = {aij * yj} + bi mod m}.
    :param a: the aij values
    :param b: the bi values
    :param m: the modulus
    :param X: a bound on the xi values
    :return: a generator generating tuples containing a list of xi values and a list of yj values
    """
    assert len(a) == len(b), "a and b lists should be of equal length."

    n1 = len(a)
    n2 = len(a[0])
    B = matrix(QQ, n1 + n2 + 1, n1 + n2 + 1)
    for i in range(n1):
        for j in range(n2):
            B[n1 + j, i] = a[i][j]

        B[i, i] = m
        B[n1 + n2, i] = b[i] - X // 2

    for j in range(n2):
        B[n1 + j, n1 + j] = X / QQ(m)

    B[n1 + n2, n1 + n2] = X

    for v in shortest_vectors(B):
        xs = [int(v[i] + X // 2) for i in range(n1)]
        ys = [(int(v[n1 + j] * m) // X) % m for j in range(n2)]
        if all(y != 0 for y in ys) and v[n1 + n2] == X:
            yield xs, ys


def dsa_known_msb(n, signatures, nonce_bitsize, msb_known):
    """
    Recovers the (EC)DSA private key and nonces if the most significant nonce bits are known.
    :param n: the modulus
    :param signatures: a list containing the signatures (a tuple of the message (hash), the r value, the s value, and the known msbs)
    :param nonce_bitsize: the amount of bits of the nonces
    :param msb_known: the amount of known most significant bits of the nonces
    :return: a generator generating tuples containing the possible private key and a list of nonces
    """
    a = []
    b = []
    X = 2 ** (nonce_bitsize - msb_known)
    shift = 2 ** (nonce_bitsize - msb_known)
    for h, r, s, msb in signatures:
        a.append([pow(s, -1, n) * r])
        b.append(pow(s, -1, n) * h - shift * msb)

    for nonces, private_key in attack(a, b, n, X):
        for i in range(len(nonces)):
            # Adding the MSB back to the nonce.
            nonces[i] = int(shift * signatures[i][3] + nonces[i])

        yield private_key[0], nonces


def dsa_known_lsb(n, signatures, nonce_bitsize, lsb_known):
    """
    Recovers the (EC)DSA private key and nonces if the least significant nonce bits are known.
    :param n: the modulus
    :param signatures: a list containing the signatures (a tuple of the message (hash), the r value, the s value, and the known lsbs)
    :param nonce_bitsize: the amount of bits of the nonces
    :param lsb_known: the amount of known least significant bits of the nonces
    :return: a generator generating tuples containing the possible private key and a list of nonces
    """
    a = []
    b = []
    X = 2 ** (nonce_bitsize - lsb_known)
    shift = 2 ** lsb_known
    invshift = pow(shift, -1, n)
    for h, r, s, lsb in signatures:
        a.append([invshift * pow(s, -1, n) * r])
        b.append(invshift * pow(s, -1, n) * h - invshift * lsb)

    for nonces, private_key in attack(a, b, n, X):
        for i in range(len(nonces)):
            # Adding the LSB back to the nonce.
            nonces[i] = int(shift * nonces[i] + signatures[i][3])

        yield private_key[0], nonces


def dsa_known_middle(n, signature1, signature2, nonce_bitsize, msb_unknown, lsb_unknown):
    """
    Recovers the (EC)DSA private key and nonces if the middle nonce bits are known.
    This is a heuristic extension which might perform worse than the methods to solve the Extended Hidden Number Problem.
    More information: De Micheli G., Heninger N., "Recovering cryptographic keys from partial information, by example" (Section 5.2.3)
    :param n: the modulus
    :param signature1: the first signature (a tuple of the message (hash), the r value, the s value, and the known middle bits)
    :param signature2: the second signature (a tuple of the message (hash), the r value, the s value, and the known middle bits)
    :param nonce_bitsize: the amount of bits of the nonces
    :param msb_unknown: the amount of unknown most significant bits of the nonces
    :param lsb_unknown: the amount of unknown least significant bits of the nonces
    :return: a tuple containing the private key, the nonce of the first signature, and the nonce of the second signature
    """
    unknown = max(msb_unknown, lsb_unknown)
    K = 2 ** unknown
    l = nonce_bitsize - msb_unknown

    h1, r1, s1, a1 = signature1
    h2, r2, s2, a2 = signature2
    t = -(pow(s1, -1, n) * s2 * r1 * pow(r2, -1, n))
    u = pow(s1, -1, n) * r1 * h2 * pow(r2, -1, n) - pow(s1, -1, n) * h1
    u_ = 2 ** lsb_unknown * a1 + 2 ** lsb_unknown * a2 * t + u

    B = matrix(ZZ, 5, 5)
    B[0] = vector(ZZ, [K, K * 2 ** l, K * t, K * t * 2 ** l, u_])
    B[1] = vector(ZZ, [0, K * n, 0, 0, 0])
    B[2] = vector(ZZ, [0, 0, K * n, 0, 0])
    B[3] = vector(ZZ, [0, 0, 0, K * n, 0])
    B[4] = vector(ZZ, [0, 0, 0, 0, K * n])

    A = matrix(ZZ, 4, 4)
    b = []
    for row, v in enumerate(shortest_vectors(B)):
        A[row] = v[:4].apply_map(lambda x: x // K)
        b.append(-v[4])
        if row == A.nrows() - 1:
            break

    assert len(b) == 4
    x1, y1, x2, y2 = A.solve_right(vector(ZZ, b))

    k1 = 2 ** l * y1 + 2 ** lsb_unknown * a1 + x1
    k2 = 2 ** l * y2 + 2 ** lsb_unknown * a2 + x2
    private_key1 = pow(r1, -1, n) * (s1 * k1 - h1) % n
    private_key2 = pow(r2, -1, n) * (s2 * k2 - h2) % n
    assert private_key1 == private_key2
    return int(private_key1), int(k1), int(k2)
