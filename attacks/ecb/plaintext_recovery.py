from Crypto.Util.Padding import pad


def _calculate_length(encrypt_oracle):
    p = bytearray()
    c = encrypt_oracle(p)
    l = len(c)
    while len(c) == l:
        p.append(0)
        c = encrypt_oracle(p)

    return l - len(p)


def attack(encrypt_oracle):
    """
    Recovers a secret which is appended to a plaintext and encrypted using ECB.
    :param encrypt_oracle: the encryption oracle
    :return: the secret
    """
    # Calculate the length of the secret.
    l = _calculate_length(encrypt_oracle)
    s = bytearray()
    # Make sure the plaintext ends with a single character in a block.
    extra = bytearray((17 - l) % 16)
    for i in range(l):
        # Try every byte.
        for j in range(256):
            padded = pad(bytes([j]) + s, 16)
            c = encrypt_oracle(padded + extra)
            # The active p block equals the active s block.
            if c[len(c) - len(padded):] == c[:len(padded)]:
                s = bytes([j]) + s
                break

        extra.append(0)

    return bytes(s)
