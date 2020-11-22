def attack(encrypt_oracle, secret_len):
    """
    Recovers a secret using the CRIME attack (CTR version).
    :param encrypt_oracle: the encryption oracle
    :param secret_len: the length of the secret to recover
    :return: the secret
    """
    padding = bytearray(i for i in range(secret_len))
    s = bytearray()
    for i in range(secret_len):
        min = None
        for j in range(256):
            l = len(encrypt_oracle(padding + s + bytes([j]) + padding))
            if min is None or l < min[0]:
                min = (l, j)

        s.append(min[1])

    return bytes(s)
