from sage.all import crt
from math import lcm


def fast_crt(X, M, segment_size=8):
    """
    Uses a divide-and-conquer algorithm to compute the CRT remainder and least common multiple.
    :param X: the remainders
    :param M: the moduli (not necessarily coprime)
    :param segment_size: the minimum size of the segments (default: 8)
    :return: a tuple containing the remainder and the least common multiple
    """
    assert len(X) == len(M)
    assert len(X) > 0
    while len(X) > 1:
        X_ = []
        M_ = []
        for i in range(0, len(X), segment_size):
            if i == len(X) - 1:
                X_.append(X[i])
                M_.append(M[i])
            else:
                X_.append(crt(X[i:i + segment_size], M[i:i + segment_size]))
                M_.append(lcm(*M[i:i + segment_size]))
        X = X_
        M = M_

    return X[0], M[0]
