import logging
import os
import sys
from math import gcd

from sage.all import is_prime
from sage.all import kronecker
from sage.all import next_prime

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.crt import fast_crt


def _generate_s(A, k):
    S = []
    for a in A:
        # Possible non-residues mod 4a of potential primes p
        Sa = set()
        for p in range(1, 4 * a, 2):
            if kronecker(a, p) == -1:
                Sa.add(p)

        # Subsets of Sa that meet the intersection requirement
        Sk = []
        for ki in k:
            assert gcd(ki, 4 * a) == 1
            Sk.append({pow(ki, -1, 4 * a) * (s + ki - 1) % (4 * a) for s in Sa})

        S.append(Sa.intersection(*Sk))

    return S


# Brute forces a combination of residues from S by backtracking
# X already contains the remainders mod each k
# M already contains each k
def _backtrack(S, A, X, M, i):
    if i == len(S):
        return fast_crt(X, M)

    M.append(4 * A[i])
    for za in S[i]:
        X.append(za)
        try:
            fast_crt(X, M)
            z, m = _backtrack(S, A, X, M, i + 1)
            if z is not None and m is not None:
                return z, m
        except ValueError:
            pass
        X.pop()

    M.pop()
    return None, None


def generate_pseudoprime(A, k2=None, k3=None, min_bit_length=0):
    """
    Generates a pseudoprime of the form p1 * p2 * p3 which passes the Miller-Rabin primality test for the provided bases.
    More information: R. Albrecht M. et al., "Prime and Prejudice: Primality Testing Under Adversarial Conditions"
    :param A: the bases
    :param k2: the k2 value (default: next_prime(A[-1]))
    :param k3: the k3 value (default: next_prime(k2))
    :param min_bit_length: the minimum bit length of the generated pseudoprime (default: 0)
    :return: a tuple containing the pseudoprime n, as well as its 3 prime factors
    """
    A.sort()
    if k2 is None:
        k2 = int(next_prime(A[-1]))
    if k3 is None:
        k3 = int(next_prime(k2))
    while True:
        logging.info(f"Trying {k2 = } and {k3 = }...")
        X = [pow(-k3, -1, k2), pow(-k2, -1, k3)]
        M = [k2, k3]
        S = _generate_s(A, M)
        logging.info(f"{S = }")
        z, m = _backtrack(S, A, X, M, 0)
        if z and m:
            logging.info(f"Found residue {z} and modulus {m}")
            i = (2 ** (min_bit_length // 3)) // m
            while True:
                p1 = int(z + i * m)
                p2 = k2 * (p1 - 1) + 1
                p3 = k3 * (p1 - 1) + 1
                if is_prime(p1) and is_prime(p2) and is_prime(p3):
                    return p1 * p2 * p3, p1, p2, p3

                i += 1
        else:
            k3 = int(next_prime(k3))
