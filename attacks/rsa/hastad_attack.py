import os
import sys
from math import gcd

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.rsa import low_exponent


def attack(N, e, c):
    """
    Recovers the plaintext from e ciphertexts, encrypted using different moduli and the same public exponent.
    :param N: the moduli
    :param e: the public exponent
    :param c: the ciphertexts
    :return: the plaintext
    """
    assert e == len(N) == len(c), "The amount of ciphertexts should be equal to e"

    for i in range(len(N)):
        for j in range(len(N)):
            if i != j and gcd(N[i], N[j]) != 1:
                raise ValueError(f"Modulus {i} and {j} share factors, Hastad's attack is impossible.")

    l = len(N)
    p = 1
    for Ni in N:
        p *= Ni

    n = [p // Ni for Ni in N]
    u = [pow(n[i], -1, N[i]) for i in range(l)]
    c = sum(map(lambda i: c[i] * u[i] * n[i], range(l))) % p
    return low_exponent.attack(e, c)
