def attack(encrypt_oracle, known_prefix, padding_byte):
    """
    Recovers a secret using the CRIME attack (CTR version).
    :param encrypt_oracle: the encryption oracle
    :param known_prefix: a known prefix of the secret to recover
    :param padding_byte: a byte which is never used in the plaintext
    :return: the secret
    """
    known_prefix = bytearray(known_prefix)
    padding_bytes = bytes([padding_byte])
    while True:
        for i in range(256):
            # Don't try the padding byte.
            if i == padding_byte:
                continue

            l1 = len(encrypt_oracle(padding_bytes + known_prefix + bytes([i]) + padding_bytes + padding_bytes))
            l2 = len(encrypt_oracle(padding_bytes + known_prefix + padding_bytes + bytes([i]) + padding_bytes))
            if l1 < l2:
                known_prefix.append(i)
                break
        else:
            return known_prefix
