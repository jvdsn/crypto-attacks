from Crypto.Util.strxor import strxor


def attack(m1, t1, m2, t2):
    m3 = bytearray(m1)
    m3 += strxor(t1, m2[:16])
    for i in range(16, len(m2), 16):
        m3 += m2[i:i + 16]
    return m3, t2
