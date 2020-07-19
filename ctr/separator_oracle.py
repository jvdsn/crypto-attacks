from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

separator = ord("|")
separator_count = 1
key = get_random_bytes(16)


def _encrypt(p):
    return AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(p)


def _invalid_separators(c):
    p = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(c)
    separators = 0
    for b in p:
        if b == separator:
            separators += 1

    return separators != separator_count


def _find_separator_positions(c):
    separator_positions = []
    c = bytearray(c)
    for i in range(len(c)):
        c[i] ^= 1
        invalid = _invalid_separators(c)
        c[i] ^= 1
        if invalid:
            c[i] ^= 2
            invalid = _invalid_separators(c)
            c[i] ^= 2
            if invalid:
                separator_positions.append(i)

    return separator_positions


def attack(c):
    """
    Recovers the plaintext using the separator oracle attack.
    :param c: the ciphertext
    :return: the plaintext
    """
    separator_positions = _find_separator_positions(c)
    c = bytearray(c)
    # Ensure that at least 1 separator is missing
    c[separator_positions[0]] ^= 1
    p = bytearray(len(c))
    for i in range(len(c)):
        if i in separator_positions:
            p[i] = separator
        else:
            c_i = c[i]
            # Try every byte until an additional separator is created.
            for b in range(256):
                c[i] = b
                if _invalid_separators(c):
                    continue

                p[i] = c_i ^ c[i] ^ separator
                break

            c[i] = c_i

    return p
