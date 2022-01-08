import logging
import os
import sys
from random import randrange

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import ceil
from shared import floor


def _insert(M, a, b):
    for i, (a_, b_) in enumerate(M):
        if b >= a_ and a <= b_:
            a = min(a, a_)
            b = min(b, b_)
            M[i] = (a, b)
            return

    M.append((a, b))
    return


# Step 1.
def _step_1(padding_oracle, n, e, c):
    s0 = 1
    c0 = c
    while not padding_oracle(c0):
        s0 = randrange(2, n)
        c0 = (c * pow(s0, e, n)) % n

    return s0, c0


# Step 2.a.
def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil(n, 3 * B)
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1

    return s


# Step 2.b.
def _step_2b(padding_oracle, n, e, c0, s):
    s += 1
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1

    return s


# Step 2.c.
def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil(2 * (b * s - 2 * B), n)
    while True:
        left = ceil(2 * B + r * n, b)
        right = floor(3 * B + r * n, a)
        for s in range(left, right + 1):
            if padding_oracle((c0 * pow(s, e, n)) % n):
                return s

        r += 1


# Step 3.
def _step_3(n, B, s, M):
    M_ = []
    for (a, b) in M:
        left = ceil(a * s - 3 * B + 1, n)
        right = floor(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, ceil(2 * B + r * n, s))
            b_ = min(b, floor(3 * B - 1 + r * n, s))
            _insert(M_, a_, b_)

    return M_


def attack(padding_oracle, n, e, c):
    """
    Recovers the plaintext using Bleichenbacher's attack.
    More information: Bleichenbacher D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
    :param padding_oracle: the padding oracle taking integers, returns True if the PKCS #1 v1.5 padding is correct, False otherwise
    :param n: the modulus
    :param e: the public exponent
    :param c: the ciphertext (integer)
    :return: the plaintext (integer)
    """
    k = ceil(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    logging.info("Executing step 1...")
    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]
    logging.info("Executing step 2.a...")
    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    logging.info("Starting while loop...")
    while True:
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                m = (a * pow(s0, -1, n)) % n
                return m
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        M = _step_3(n, B, s, M)
