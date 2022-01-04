def attack(encrypt_oracle):
    """
    Recovers a secret which is appended to a plaintext and encrypted using ECB.
    :param encrypt_oracle: the encryption oracle
    :return: the secret
    """
    secret = bytearray()
    while True:
        prefix = bytes(15 - (len(secret) % 16))
        p = bytearray(prefix + secret + b"0" + prefix)
        end1 = len(prefix) + len(secret) + 1
        end2 = 2 * end1
        for i in range(256):
            p[end1 - 1] = i
            c = encrypt_oracle(p)
            if c[end1 - 16:end1] == c[end2 - 16:end2]:
                secret.append(i)
                break
        else:
            secret.pop()
            break

    return bytes(secret)
