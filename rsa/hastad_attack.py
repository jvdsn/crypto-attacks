from math import gcd

from sage.all import Integer


def attack(e, moduli, ciphertexts):
    """
    Recovers the plaintext from e ciphertexts, encrypted using different moduli and the same public exponent.
    :param e: the public exponent
    :param moduli: the moduli
    :param ciphertexts: the ciphertexts
    :return: the plaintext
    """
    for i in range(len(moduli)):
        for j in range(len(moduli)):
            if i != j and gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(f"Modulus {i} and {j} share factors, Hastad's attack is impossible.")

    l = len(moduli)
    p = 1
    for modulus in moduli:
        p *= modulus

    n = list(map(lambda i: p // i, moduli))
    u = list(map(lambda i: pow(n[i], -1, moduli[i]), range(l)))
    c = sum(map(lambda i: ciphertexts[i] * u[i] * n[i], range(l))) % p
    return Integer(c).nth_root(e)
