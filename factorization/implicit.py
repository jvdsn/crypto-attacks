from math import gcd

from sage.all import ZZ
from sage.all import matrix


def factorize_msb(moduli, bitsize, shared_bitsize):
    """
    Factorizes the moduli when some most significant bits are equal among multiples of a prime factor.
    More information: Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli" (Section 4)
    :param moduli: the moduli
    :param bitsize: the amount of bits of the moduli
    :param shared_bitsize: the amount of shared most significant bits
    :return: a list containing a tuple of the factors of each modulus, or None if the factors were not found
    """
    L = matrix(ZZ, len(moduli), len(moduli))
    L[0, 0] = 2 ** (bitsize - shared_bitsize)
    for i in range(1, len(moduli)):
        L[0, i] = moduli[i]

    for i in range(1, len(moduli)):
        L[i, i] = -moduli[0]

    L = L.LLL()

    for row in range(L.nrows()):
        factors = []
        for col in range(L.ncols()):
            modulus = moduli[col]
            q = gcd(L[row, col], modulus)
            if 1 < q < modulus and modulus % q == 0:
                factors.append((modulus // q, q))

        if len(factors) == len(moduli):
            return factors


def factorize_lsb(moduli, bitsize, shared_bitsize):
    """
    Factorizes the moduli when some least significant bits are equal among multiples of a prime factor.
    More information: Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli" (Section 6)
    :param moduli: the moduli
    :param bitsize: the amount of bits of the moduli
    :param shared_bitsize: the amount of shared least significant bits
    :return: a list containing a tuple of the factors of each modulus, or None if the factors were not found
    """
    L = matrix(ZZ, len(moduli), len(moduli))
    L[0, 0] = 1
    for i in range(1, len(moduli)):
        L[0, i] = pow(moduli[0], -1, 2 ** shared_bitsize) * moduli[i] % (2 ** shared_bitsize)

    for i in range(1, len(moduli)):
        L[i, i] = -2 ** shared_bitsize

    L = L.LLL()

    for row in range(L.nrows()):
        factors = []
        for col in range(L.ncols()):
            modulus = moduli[col]
            q = gcd(L[row, col], modulus)
            if 1 < q < modulus and modulus % q == 0:
                factors.append((modulus // q, q))

        if len(factors) == len(moduli):
            return factors
