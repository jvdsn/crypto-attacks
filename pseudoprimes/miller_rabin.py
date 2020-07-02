from sage.all import crt
from sage.all import inverse_mod
from sage.all import is_prime
from sage.all import legendre_symbol
from sage.all import next_prime


def _generate_s(bases, k2, k3):
    s = []
    for b in bases:
        s_b = set()
        for p in range(1, 4 * b, 2):
            if legendre_symbol(b, p) == -1:
                s_b.add(p)

        s.append(s_b)

    for i in range(len(s)):
        mod = 4 * bases[i]
        inv2 = inverse_mod(k2, mod)
        inv3 = inverse_mod(k3, mod)
        s2 = set()
        s3 = set()
        for z in s[i]:
            s2.add(inv2 * (z + k2 - 1) % mod)
            s3.add(inv3 * (z + k3 - 1) % mod)

        s[i] &= s2 & s3

    return s


# Brute forces a combination of residues from s by backtracking
def _backtrack(s, bases, residues, moduli, i):
    if i == len(s):
        combined_modulus = 1
        for modulus in moduli:
            combined_modulus *= modulus

        return crt(residues, moduli), combined_modulus

    moduli.append(4 * bases[i])
    for residue in s[i]:
        residues.append(residue)
        try:
            crt(residues, moduli)
            ans = _backtrack(s, bases, residues, moduli, i + 1)
            if ans:
                return ans
        except ValueError:
            pass
        residues.pop()

    moduli.pop()
    return None, None


def generate_pseudoprime(bases, min_bitsize=0):
    """
    Generates a pseudoprime which passes the Miller-Rabin primality test for the provided bases.
    :param bases: the bases
    :param min_bitsize: the minimum bitsize of the generated pseudoprime (default: 0)
    :return: a tuple containing the pseudoprime, as well as its 3 prime factors
    """
    bases.sort()
    k2 = next_prime(bases[-1])
    k3 = next_prime(k2)
    while True:
        residues = [inverse_mod(-k2, k3), inverse_mod(-k3, k2)]
        moduli = [k3, k2]
        s = _generate_s(bases, k2, k3)
        residue, modulus = _backtrack(s, bases, residues, moduli, 0)
        if residue and modulus:
            i = (2 ** (min_bitsize // 3)) // modulus
            while True:
                p1 = residue + i * modulus
                p2 = k2 * (p1 - 1) + 1
                p3 = k3 * (p1 - 1) + 1
                if is_prime(p1) and is_prime(p2) and is_prime(p3):
                    return p1 * p2 * p3, p1, p2, p3

                i += 1
        else:
            k3 = next_prime(k3)
