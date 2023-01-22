import os
import sys

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.partial_integer import PartialInteger


def attack(n, e, sv, sf):
    """
    Recovers the bits of the private exponent d that were flipped during generation of signatures.
    More faulty signatures reveal more bits of d, assuming the bit flip positions are different.
    :param n: the modulus
    :param e: the public exponent
    :param sv: the valid signature
    :param sf: the list of faulty signatures: for each entry in this list, at most one bit in d should have been flipped during signature generation
    :return: a PartialInteger containing the known and unknown bits of d
    """
    d_bits = [None] * n.bit_length()
    m = 2
    mi = {pow(m, 2 ** i, n): i for i in range(n.bit_length())}
    for sfi in sf:
        di0 = pow(sv, -1, n) * sfi % n
        di1 = sv * pow(sfi, -1, n) % n
        if di0 in mi:
            d_bits[mi[di0]] = 0
        if di1 in mi:
            d_bits[mi[di1]] = 1

    return PartialInteger.from_bits_le(d_bits)
