from sage.all import Matrix
from sage.all import QQ


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


def dsa_known_msb(p, signatures, nonce_bitsize, msb_known):
    t = []
    a = []
    B = 2 ** (nonce_bitsize - msb_known)
    shift = 2 ** (nonce_bitsize - msb_known)
    for h, r, s, msb in signatures:
        t.append(pow(s, -1, p) * r)
        a.append(pow(s, -1, p) * h - shift * msb)

    private_key, nonces = attack(p, t, a, B)
    for i in range(len(nonces)):
        # Adding the MSB back to the nonce.
        nonces[i] = shift * signatures[i][3] + nonces[i]

    return private_key, nonces


def dsa_known_lsb(p, signatures, nonce_bitsize, lsb_known):
    t = []
    a = []
    B = 2 ** (nonce_bitsize - lsb_known)
    shift = 2 ** lsb_known
    invshift = pow(shift, -1, p)
    for h, r, s, lsb in signatures:
        t.append(invshift * pow(s, -1, p) * r)
        a.append(invshift * pow(s, -1, p) * h - invshift * lsb)

    private_key, nonces = attack(p, t, a, B)
    for i in range(len(nonces)):
        # Adding the LSB back to the nonce.
        nonces[i] = shift * nonces[i] + signatures[i][3]

    return private_key, nonces
