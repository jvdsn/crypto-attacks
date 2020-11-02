from sage.all import Matrix
from sage.all import QQ


def attack(t, a, p, bound):
    """
    Solves the hidden number problem using an attack based on the shortest vector problem.
    The hidden number problem is defined as finding y such that {x - t * y + a = 0 mod p}.
    More information: Breitner J., Heninger N., "Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies"
    :param t: the t values
    :param a: the a values
    :param p: the prime
    :param bound: a bound on the x values
    :return: a tuple containing y, and a list of x values
    """
    m = len(t)
    lattice = Matrix(QQ, m + 2, m + 2)
    for i in range(m):
        lattice[i, i] = p

    lattice[m] = t + [bound / QQ(p), 0]
    lattice[m + 1] = a + [0, bound]

    basis = lattice.LLL()

    for row in basis.rows():
        y = (int(row[m] * p) // bound) % p
        if y != 0:
            return y, list(map(int, row[:m]))
