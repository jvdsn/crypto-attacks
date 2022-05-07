import logging


def shortest_vectors(B):
    """
    Computes the shortest non-zero vectors in a lattice.
    :param B: the basis of the lattice
    :return: a generator generating the shortest non-zero vectors
    """
    logging.debug(f"Computing shortest vectors in {B.nrows()} x {B.ncols()} matrix...")
    B = B.LLL()

    for row in B.rows():
        if not row.is_zero():
            yield row


# Babai's Nearest Plane Algorithm from "Lecture 3: CVP Algorithm" by Oded Regev.
def _closest_vectors_babai(B, t):
    B = B.LLL()

    for G in B.gram_schmidt():
        b = t
        for j in reversed(range(B.nrows())):
            b -= round((b * G[j]) / (G[j] * G[j])) * B[j]

        yield t - b


def _closest_vectors_embedding(B, t):
    B_ = B.new_matrix(B.nrows() + 1, B.ncols() + 1)
    for row in range(B.nrows()):
        for col in range(B.ncols()):
            B_[row, col] = B[row, col]

    for col in range(B.ncols()):
        B_[B.nrows(), col] = t[col]

    B_[B.nrows(), B.ncols()] = 1
    yield from shortest_vectors(B_)


def closest_vectors(B, t, algorithm="embedding"):
    """
    Computes the closest vectors in a lattice to a target vector.
    :param B: the basis of the lattice
    :param t: the target vector
    :param algorithm: the algorithm to use, can be "babai" or "embedding" (default: "embedding")
    :return: a generator generating the shortest non-zero vectors
    """
    logging.debug(f"Computing closest vectors in {B.nrows()} x {B.ncols()} matrix...")
    if algorithm == "babai":
        yield from _closest_vectors_babai(B, t)
    elif algorithm == "embedding":
        yield from _closest_vectors_embedding(B, t)
