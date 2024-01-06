def attack(p, m, c1, c2, c1_, c2_):
    """
    Recovers a secret plaintext encrypted using the same nonce as a previous, known plaintext.
    :param p: the prime used in the ElGamal scheme
    :param m: the known plaintext
    :param c1: the ciphertext of the known plaintext
    :param c2: the ciphertext of the known plaintext
    :param c1_: the ciphertext of the secret plaintext
    :param c2_: the ciphertext of the secret plaintext
    :return: the secret plaintext
    """
    s = c2 * pow(m, -1, p) % p
    m_ = c2_ * pow(s, -1, p) % p
    return int(m_)
