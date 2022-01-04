def _get_prefix_padding(encrypt_oracle, paddings):
    check = b"\01" * 32
    for i in range(16):
        prefix_padding = paddings[16 - i]
        c = encrypt_oracle(prefix_padding + check)
        if c[16:32] == c[32:48]:
            return prefix_padding


def attack(encrypt_oracle, unused_byte=0):
    """
    Recovers a secret which is appended to a plaintext and encrypted using ECB.
    In this scenario, the encryption oracle prepends a constant, random prefix (length 0 to 16) to the plaintext.
    :param encrypt_oracle: the encryption oracle
    :param unused_byte: a byte that's never used in the secret or random prefix
    :return: the secret
    """
    # 17 here because _get_prefix_padding needs paddings[16].
    paddings = [bytes([unused_byte] * i) for i in range(17)]
    prefix_padding = _get_prefix_padding(encrypt_oracle, paddings)
    secret = bytearray()
    while True:
        padding = paddings[15 - (len(secret) % 16)]
        p = bytearray(prefix_padding + padding + secret + b"0" + padding)
        byte_index = len(prefix_padding) + len(padding) + len(secret)
        end1 = 16 + len(padding) + len(secret) + 1
        end2 = end1 + len(padding) + len(secret) + 1
        for i in range(256):
            p[byte_index] = i
            c = encrypt_oracle(p)
            if c[end1 - 16:end1] == c[end2 - 16:end2]:
                secret.append(i)
                break
        else:
            secret.pop()
            break

    return bytes(secret)
