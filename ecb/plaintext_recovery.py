from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)
secret = get_random_bytes(16)


def _encrypt(p):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(p + secret, 16))


def _calculate_length():
    p = bytearray()
    c = _encrypt(p)
    l = len(c)
    while len(c) == l:
        p.append(0)
        c = _encrypt(p)

    return l - len(p)


def attack():
    """
    Recovers a secret which is appended to a plaintext and encrypted using ECB.
    :return: the secret
    """
    # Calculate the length of the secret.
    l = _calculate_length()
    s = bytearray()
    # Make sure the plaintext ends with a single character in a block.
    extra = bytearray((17 - l) % 16)
    for i in range(l):
        s.insert(0, 0)
        # Try every btyte.
        for j in range(256):
            s[0] = j
            padded = pad(s, 16)
            c = _encrypt(padded + extra)
            # The active p block equals the active s block.
            if c[len(c) - len(padded):] == c[:len(padded)]:
                break

        extra.append(0)

    return bytes(s)
