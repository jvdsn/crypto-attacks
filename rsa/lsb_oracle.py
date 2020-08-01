from sage.all import Integer


def attack(n, e, c, oracle):
    """
    Recovers the plaintext from the ciphertext using the LSB oracle attack.
    :param n: the modulus
    :param e: the public exponent
    :param c: the encrypted message
    :param oracle: a function which returns the last bit of a plaintext for a given ciphertext
    :return: the plaintext
    """
    left = Integer(0)
    right = Integer(n)
    while right - left > 1:
        c = (c * pow(2, e, n)) % n
        if oracle(c) == 0:
            right = (right + left) / 2
        else:
            left = (right + left) / 2

    return int(right)
