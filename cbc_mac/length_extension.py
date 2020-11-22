from Crypto.Util.strxor import strxor


def attack(m1, t1, m2, t2):
    """
    Uses a length extension attack to forge a message and tag pair for CBC-MAC.
    :param m1: the first message
    :param t1: the tag of the first message
    :param m2: the second message
    :param t2: the tag of the second message
    :return: a tuple containing a valid message and tag for CBC-MAC
    """
    m3 = bytearray(m1)
    m3 += strxor(t1, m2[:16])
    for i in range(16, len(m2), 16):
        m3 += m2[i:i + 16]

    return m3, t2
