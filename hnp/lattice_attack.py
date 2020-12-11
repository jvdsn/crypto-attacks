from sage.all import Matrix
from sage.all import QQ
from sage.all import ZZ
from sage.all import vector


def attack(p, t, a, B):
    """
    Solves the hidden number problem using an attack based on the shortest vector problem.
    The hidden number problem is defined as finding y such that {x_i - t_i * y + a_i = 0 mod p}.
    More information: Breitner J., Heninger N., "Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies"
    :param p: the modulus
    :param t: the t_i values
    :param a: the a_i values
    :param B: a bound on the x values
    :return: a tuple containing y, and a list of x values
    """
    assert len(t) == len(a), "t and a lists should be of equal length."

    m = len(t)
    lattice = Matrix(QQ, m + 2, m + 2)
    for i in range(m):
        lattice[i, i] = p

    lattice[m] = t + [B / QQ(p), 0]
    lattice[m + 1] = a + [0, B]

    basis = lattice.LLL()

    for row in basis.rows():
        y = (int(row[m] * p) // B) % p
        if y != 0:
            return int(y), list(map(int, row[:m]))


def dsa_known_msb(n, signatures, nonce_bitsize, msb_known):
    """
    Recovers the (EC)DSA private key and nonces if the most significant nonce bits are known.
    :param n: the modulus
    :param signatures: a list containing the signatures (a tuple of the message (hash), the r value, the s value, and the known msbs)
    :param nonce_bitsize: the amount of bits of the nonces
    :param msb_known: the amount of known most significant bits of the nonces
    :return: a tuple containing the private key and a list of nonces
    """
    t = []
    a = []
    B = 2 ** (nonce_bitsize - msb_known)
    shift = 2 ** (nonce_bitsize - msb_known)
    for h, r, s, msb in signatures:
        t.append(pow(s, -1, n) * r)
        a.append(pow(s, -1, n) * h - shift * msb)

    private_key, nonces = attack(n, t, a, B)
    for i in range(len(nonces)):
        # Adding the MSB back to the nonce.
        nonces[i] = int(shift * signatures[i][3] + nonces[i])

    return int(private_key), nonces


def dsa_known_lsb(n, signatures, nonce_bitsize, lsb_known):
    """
    Recovers the (EC)DSA private key and nonces if the least significant nonce bits are known.
    :param n: the modulus
    :param signatures: a list containing the signatures (a tuple of the message (hash), the r value, the s value, and the known lsbs)
    :param nonce_bitsize: the amount of bits of the nonces
    :param lsb_known: the amount of known least significant bits of the nonces
    :return: a tuple containing the private key and a list of nonces
    """
    t = []
    a = []
    B = 2 ** (nonce_bitsize - lsb_known)
    shift = 2 ** lsb_known
    invshift = pow(shift, -1, n)
    for h, r, s, lsb in signatures:
        t.append(invshift * pow(s, -1, n) * r)
        a.append(invshift * pow(s, -1, n) * h - invshift * lsb)

    private_key, nonces = attack(n, t, a, B)
    for i in range(len(nonces)):
        # Adding the LSB back to the nonce.
        nonces[i] = int(shift * nonces[i] + signatures[i][3])

    return int(private_key), nonces


def dsa_known_middle(n, signature1, signature2, nonce_bitsize, msb_unknown, lsb_unknown):
    """
    Recovers the (EC)DSA private key and nonces if the middle nonce bits are known.
    This is a heuristic extension which might perform worse than the methods to solve the Extended Hidden Number Problem
    More information: De Micheli, G., Heninger, N., "Recovering cryptographic keys from partial information, by example" (Section 5.2.3)
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

    B = Matrix(ZZ, 5)
    B[0] = vector(ZZ, [K, K * 2 ** l, K * t, K * t * 2 ** l, u_])
    B[1] = vector(ZZ, [0, K * n, 0, 0, 0])
    B[2] = vector(ZZ, [0, 0, K * n, 0, 0])
    B[3] = vector(ZZ, [0, 0, 0, K * n, 0])
    B[4] = vector(ZZ, [0, 0, 0, 0, K * n])

    B = B.LLL()

    M = Matrix(ZZ, 4)
    v = []
    for row, vec in enumerate(B[:4]):
        M[row] = vec[:4].apply_map(lambda x: x // K)
        v.append(-vec[4])

    x1, y1, x2, y2 = M.solve_right(vector(ZZ, v))

    k1 = 2 ** l * y1 + 2 ** lsb_unknown * a1 + x1
    k2 = 2 ** l * y2 + 2 ** lsb_unknown * a2 + x2
    private_key1 = pow(r1, -1, n) * (s1 * k1 - h1) % n
    private_key2 = pow(r2, -1, n) * (s2 * k2 - h2) % n
    assert private_key1 == private_key2

    return int(private_key1), int(k1), int(k2)
