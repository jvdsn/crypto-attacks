from math import gcd

from sage.all import GF
from sage.all import is_prime_power


def attack(outputs, modulus=None, multiplier=None, increment=None):
    """
    Recovers the parameters from a linear congruential generator.
    If no modulus is provided, attempts to recover the modulus from the outputs (may require many outputs).
    If no multiplier is provided, attempts to recover the multiplier from the outputs (requires at least 3 outputs).
    If no increment is provided, attempts to recover the increment from the outputs (requires at least 2 outputs).
    :param outputs: the sequential output values obtained from the LCG
    :param modulus: the modulus of the LCG (can be None)
    :param multiplier: the multiplier of the LCG (can be None)
    :param increment: the increment of the LCG (can be None)
    :return: a tuple containing the modulus, multiplier, and the increment
    """
    if modulus is None:
        assert len(outputs) >= 4, "At least 4 outputs are required to recover the modulus"
        for i in range(len(outputs) - 3):
            d0 = outputs[i + 1] - outputs[i]
            d1 = outputs[i + 2] - outputs[i + 1]
            d2 = outputs[i + 3] - outputs[i + 2]
            g = d2 * d0 - d1 * d1
            modulus = g if modulus is None else gcd(g, modulus)

        assert is_prime_power(modulus), "Modulus must be a prime power, try providing more outputs"

    gf = GF(modulus)
    if multiplier is None:
        assert len(outputs) >= 3, "At least 3 outputs are required to recover the multiplier"
        x0 = gf(outputs[0])
        x1 = gf(outputs[1])
        x2 = gf(outputs[2])
        multiplier = (x2 - x1) / (x1 - x0)

    if increment is None:
        assert len(outputs) >= 2, "At least 2 outputs are required to recover the multiplier"
        x0 = gf(outputs[0])
        x1 = gf(outputs[1])
        increment = x1 - multiplier * x0

    return modulus, multiplier, increment
