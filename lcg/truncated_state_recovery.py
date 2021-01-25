from sage.all import QQ
from sage.all import ZZ
from sage.all import matrix
from sage.all import vector


def attack(outputs, state_bitsize, output_bitsize, modulus, multiplier, increment):
    """
    Recovers the states associated with the outputs from a truncated linear congruential generator.
    More information: Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"
    :param outputs: the sequential output values obtained from the truncated LCG (the states truncated to output_bitsize most significant bits)
    :param state_bitsize: the size in bits of the states
    :param output_bitsize: the size in bits of the outputs
    :param modulus: the modulus of the LCG
    :param multiplier: the multiplier of the LCG
    :param increment: the increment of the LCG
    :return: a list containing the states associated with the provided outputs
    """
    diff_bitsize = state_bitsize - output_bitsize

    # Preparing for the lattice reduction.
    delta = increment % modulus
    y = vector(outputs)
    for i in range(len(y)):
        # Shift output value to the MSBs and remove the increment.
        y[i] = (y[i] << diff_bitsize) - delta
        delta = (multiplier * delta + increment) % modulus

    # This lattice only works for increment = 0.
    M = matrix(ZZ, len(y), len(y))
    M[0, 0] = modulus
    for i in range(1, len(y)):
        M[i, 0] = multiplier ** i
        M[i, i] = -1

    L = M.LLL()

    # Finding the target value to solve the equation for the states.
    target = L * y
    for i in range(len(target)):
        target[i] = round(QQ(target[i]) / modulus) * modulus - target[i]

    # Recovering the states
    delta = increment % modulus
    states = list(L.solve_right(target))
    for i, state in enumerate(states):
        # Adding the MSBs and the increment back again.
        states[i] = int(y[i] + state + delta)
        delta = (multiplier * delta + increment) % modulus

    return states
