from sage.all import ZZ


def attack(N, e, c, oracle):
    """
    Recovers the plaintext from the ciphertext using the LSB oracle attack.
    :param N: the modulus
    :param e: the public exponent
    :param c: the encrypted message
    :param oracle: a function which returns the last bit of a plaintext for a given ciphertext
    :return: the plaintext
    """
    left = ZZ(0)
    right = ZZ(N)
    while right - left > 1:
        c = (c * pow(2, e, N)) % N
        if oracle(c) == 0:
            right = (right + left) / 2
        else:
            left = (right + left) / 2

    return int(right)
