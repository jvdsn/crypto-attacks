def _find_separator_positions(separator_oracle, c):
    separator_positions = []
    c = bytearray(c)
    for i in range(len(c)):
        c[i] ^= 1
        valid = separator_oracle(c)
        c[i] ^= 1
        if not valid:
            c[i] ^= 2
            valid = separator_oracle(c)
            c[i] ^= 2
            if not valid:
                separator_positions.append(i)

    return separator_positions


def attack(separator_oracle, separator_byte, c):
    """
    Recovers the plaintext using the separator oracle attack.
    :param separator_oracle: the separator oracle, returns True if the separators are correct, False otherwise
    :param separator_byte: the separator which is used in the separator oracle
    :param c: the ciphertext
    :return: the plaintext
    """
    separator_positions = _find_separator_positions(separator_oracle, c)
    c = bytearray(c)
    # Ensure that at least 1 separator is missing.
    c[separator_positions[0]] ^= 1
    p = bytearray(len(c))
    for i in range(len(c)):
        if i in separator_positions:
            p[i] = separator_byte
        else:
            c_i = c[i]
            # Try every byte until an additional separator is created.
            for b in range(256):
                c[i] = b
                if separator_oracle(c):
                    p[i] = c_i ^ c[i] ^ separator_byte
                    break

            c[i] = c_i

    return p
