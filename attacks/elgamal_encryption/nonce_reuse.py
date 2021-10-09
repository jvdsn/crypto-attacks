def attack(p, m1, c1, d1, c2, d2):
    """
    Recovers a secret plaintext encrypted using the same nonce as a previous, known plaintext.
    :param p: the prime used in the ElGamal scheme
    :param m1: the known plaintext
    :param c1: the ciphertext of the known plaintext
    :param d1: the ciphertext of the known plaintext
    :param c2: the ciphertext of the secret plaintext
    :param d2: the ciphertext of the secret plaintext
    :return: the secret plaintext
    """
    return int(pow(d1, -1, p) * d2 * m1 % p)
