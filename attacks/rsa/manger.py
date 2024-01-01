import logging
import os
import sys

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import ceil_div
from shared import floor_div


# Step 1.
def _step_1(padding_oracle, n, e, c):
    f1 = 2
    while padding_oracle((pow(f1, e, n) * c) % n):
        f1 *= 2

    return f1


# Step 2.
def _step_2(padding_oracle, n, e, c, B, f1):
    f2 = floor_div(n + B, B) * f1 // 2
    while not padding_oracle((pow(f2, e, n) * c) % n):
        f2 += f1 // 2

    return f2


# Step 3.
def _step_3(padding_oracle, n, e, c, B, f2):
    mmin = ceil_div(n, f2)
    mmax = floor_div(n + B, f2)
    while mmin < mmax:
        f = floor_div(2 * B, mmax - mmin)
        i = floor_div(f * mmin, n)
        f3 = ceil_div(i * n, mmin)
        if padding_oracle((pow(f3, e, n) * c) % n):
            mmax = floor_div(i * n + B, f3)
        else:
            mmin = ceil_div(i * n + B, f3)
    return mmin


def attack(padding_oracle, n, e, c):
    """
    Recovers the plaintext using Manger's attack.
    More information: Manger J., "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"
    :param padding_oracle: the padding oracle taking integers, returns True if the PKCS #1 OAEP padding length is correct, False otherwise
    :param n: the modulus
    :param e: the public exponent
    :param c: the ciphertext (integer)
    :return: the plaintext (integer)
    """
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 1))
    # TODO: extend at some point?
    assert 2 * B < n
    logging.info("Executing step 1...")
    f1 = _step_1(padding_oracle, n, e, c)
    logging.info("Executing step 2...")
    f2 = _step_2(padding_oracle, n, e, c, B, f1)
    logging.info("Executing step 3...")
    m = _step_3(padding_oracle, n, e, c, B, f2)
    return m
