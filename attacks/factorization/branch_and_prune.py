import logging
import os
import sys
from itertools import product

from sage.all import solve_mod
from sage.all import var

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import bits_to_int_le
from shared import int_to_bits_le


# Section 3.
def _tau(x):
    i = 0
    while x % 2 == 0:
        x //= 2
        i += 1

    return i


# Section 2.
def _find_k(N, e, d_bits):
    best_match_count = 0
    best_k = None
    best_d__bits = None
    # Enumerate every possible k value.
    for k in range(1, e):
        d_ = (k * (N + 1) + 1) // e
        d__bits = int_to_bits_le(d_, len(d_bits))
        match_count = 0
        # Only check the most significant half.
        for i in range(len(d_bits) // 2 - 2):
            if d_bits[-(i + 1)] == d__bits[-(i + 1)]:
                match_count += 1

        # Update the best match for d.
        if match_count > best_match_count:
            best_match_count = match_count
            best_k = k
            best_d__bits = d__bits

    return best_k, best_d__bits


# Section 2.
def _correct_msb(d_bits, d__bits):
    # Correcting the most significant half of d.
    for i in range(len(d_bits) // 2 - 2):
        d_bits[-(i + 1)] = d__bits[-(i + 1)]


# Section 3.
def _correct_lsb(e, d_bits, exp):
    # Correcting the least significant bits of d.
    # Also works for dp and dq, just with a different exponent.
    inv = pow(e, -1, 2 ** exp)
    for i in range(exp):
        d_bits[i] = (inv >> i) & 1


# Branch and prune for the case with p and q bits known.
def _branch_and_prune_pq(N, p, q, i):
    p_ = bits_to_int_le(p, i)
    q_ = bits_to_int_le(q, i)
    if i == len(p) or i == len(q):
        yield p_, q_
    else:
        c1 = ((N - p_ * q_) >> i) & 1
        p_prev = p[i]
        q_prev = q[i]
        p_possible = [0, 1] if p_prev is None else [p_prev]
        q_possible = [0, 1] if q_prev is None else [q_prev]
        for p_bit, q_bit in product(p_possible, q_possible):
            # Addition modulo 2 is just xor.
            if p_bit ^ q_bit == c1:
                p[i] = p_bit
                q[i] = q_bit
                yield from _branch_and_prune_pq(N, p, q, i + 1)

        p[i] = p_prev
        q[i] = q_prev


# Branch and prune for the case with p, q, and d bits known.
def _branch_and_prune_pqd(N, e, k, tk, p, q, d, i):
    p_ = bits_to_int_le(p, i)
    q_ = bits_to_int_le(q, i)
    if i == len(p) or i == len(q):
        yield p_, q_
    else:
        d_ = bits_to_int_le(d, i)
        c1 = ((N - p_ * q_) >> i) & 1
        c2 = ((k * (N + 1) + 1 - k * (p_ + q_) - e * d_) >> (i + tk)) & 1
        p_prev = p[i]
        q_prev = q[i]
        d_prev = d[i + tk]
        p_possible = [0, 1] if p_prev is None else [p_prev]
        q_possible = [0, 1] if q_prev is None else [q_prev]
        d_possible = [0, 1] if d_prev is None else [d_prev]
        for p_bit, q_bit, d_bit in product(p_possible, q_possible, d_possible):
            # Addition modulo 2 is just xor.
            if p_bit ^ q_bit == c1 and d_bit ^ p_bit ^ q_bit == c2:
                p[i] = p_bit
                q[i] = q_bit
                d[i + tk] = d_bit
                yield from _branch_and_prune_pqd(N, e, k, tk, p, q, d, i + 1)

        p[i] = p_prev
        q[i] = q_prev
        d[i + tk] = d_prev


# Branch and prune for the case with p, q, d, dp, and dq bits known.
def _branch_and_prune_pqddpdq(N, e, k, tk, kp, tkp, kq, tkq, p, q, d, dp, dq, i):
    p_ = bits_to_int_le(p, i)
    q_ = bits_to_int_le(q, i)
    if i == len(p) or i == len(q):
        yield p_, q_
    else:
        d_ = bits_to_int_le(d, i)
        dp_ = bits_to_int_le(dp, i)
        dq_ = bits_to_int_le(dq, i)
        c1 = ((N - p_ * q_) >> i) & 1
        c2 = ((k * (N + 1) + 1 - k * (p_ + q_) - e * d_) >> (i + tk)) & 1
        c3 = ((kp * (p_ - 1) + 1 - e * dp_) >> (i + tkp)) & 1
        c4 = ((kq * (q_ - 1) + 1 - e * dq_) >> (i + tkq)) & 1
        p_prev = p[i]
        q_prev = q[i]
        d_prev = d[i + tk]
        dp_prev = dp[i + tkp]
        dq_prev = dq[i + tkq]
        p_possible = [0, 1] if p_prev is None else [p_prev]
        q_possible = [0, 1] if q_prev is None else [q_prev]
        d_possible = [0, 1] if d_prev is None else [d_prev]
        dp_possible = [0, 1] if dp_prev is None else [dp_prev]
        dq_possible = [0, 1] if dq_prev is None else [dq_prev]
        for p_bit, q_bit, d_bit, dp_bit, dq_bit in product(p_possible, q_possible, d_possible, dp_possible, dq_possible):
            # Addition modulo 2 is just xor.
            if p_bit ^ q_bit == c1 and d_bit ^ p_bit ^ q_bit == c2 and dp_bit ^ p_bit == c3 and dq_bit ^ q_bit == c4:
                p[i] = p_bit
                q[i] = q_bit
                d[i + tk] = d_bit
                dp[i + tkp] = dp_bit
                dq[i + tkq] = dq_bit
                yield from _branch_and_prune_pqddpdq(N, e, k, tk, kp, tkp, kq, tkq, p, q, d, dp, dq, i + 1)

        p[i] = p_prev
        q[i] = q_prev
        d[i + tk] = d_prev
        dp[i + tkp] = dp_prev
        dq[i + tkq] = dq_prev


def factorize_pq(N, p_bits, q_bits):
    """
    Factorizes n when some bits of p and q are known.
    If at least 57% of the bits are known, this attack should be polynomial time, however, smaller percentages might still work.
    More information: Heninger N., Shacham H., "Reconstructing RSA Private Keys from Random Key Bits"
    :param N: the modulus
    :param p_bits: an array representing the bits (0, 1, or None if unknown) of p, in big endian format
    :param q_bits: an array representing the bits (0, 1, or None if unknown) of q, in big endian format
    :return: a tuple containing the prime factors
    """
    assert len(p_bits) == len(q_bits), "p and q bits should be of equal length."

    # Big endian to little endian.
    # Also make a copy to ensure we don't modify the original bits.
    p_bits = p_bits[::-1]
    q_bits = q_bits[::-1]

    # p and q are prime, odd.
    p_bits[0] = 1
    q_bits[0] = 1
    logging.info("Starting branch and prune algorithm...")
    for p, q in _branch_and_prune_pq(N, p_bits, q_bits, 1):
        if p * q == N:
            return int(p), int(q)


def factorize_pqd(N, e, p_bits, q_bits, d_bits):
    """
    Factorizes n when some bits of p, q, and d are known.
    If at least 42% of the bits are known, this attack should be polynomial time, however, smaller percentages might still work.
    More information: Heninger N., Shacham H., "Reconstructing RSA Private Keys from Random Key Bits"
    :param N: the modulus
    :param e: the public exponent
    :param p_bits: an array representing the bits (0, 1, or None if unknown) of p, in big endian format
    :param q_bits: an array representing the bits (0, 1, or None if unknown) of q, in big endian format
    :param d_bits: an array representing the bits (0, 1, or None if unknown) of d, in big endian format
    :return: a tuple containing the prime factors
    """
    assert len(p_bits) == len(q_bits), "p and q bits should be of equal length."

    # Big endian to little endian.
    # Also make a copy to ensure we don't modify the original bits.
    p_bits = p_bits[::-1]
    q_bits = q_bits[::-1]
    d_bits = d_bits[::-1]

    # p and q are prime, odd.
    p_bits[0] = 1
    q_bits[0] = 1

    # Because e is small, k can be found by brute force.
    logging.info("Brute forcing k...")
    k, d__bits = _find_k(N, e, d_bits)
    logging.info(f"Found k = {k}")

    _correct_msb(d_bits, d__bits)

    tk = _tau(k)
    _correct_lsb(e, d_bits, 2 + tk)

    logging.info("Starting branch and prune algorithm...")
    for p, q in _branch_and_prune_pqd(N, e, k, tk, p_bits, q_bits, d_bits, 1):
        if p * q == N:
            return int(p), int(q)


def factorize_pqddpdq(N, e, p_bits, q_bits, d_bits, dp_bits, dq_bits):
    """
    Factorizes n when some bits of p, q, d, dp, and dq are known.
    If at least 27% of the bits are known, this attack should be polynomial time, however, smaller percentages might still work.
    More information: Heninger N., Shacham H., "Reconstructing RSA Private Keys from Random Key Bits"
    :param N: the modulus
    :param e: the public exponent
    :param p_bits: an array representing the bits (0, 1, or None if unknown) of p, in big endian format
    :param q_bits: an array representing the bits (0, 1, or None if unknown) of q, in big endian format
    :param d_bits: an array representing the bits (0, 1, or None if unknown) of d, in big endian format
    :param dp_bits: an array representing the bits (0, 1, or None if unknown) of dp, in big endian format
    :param dq_bits: an array representing the bits (0, 1, or None if unknown) of dq, in big endian format
    :return: a tuple containing the prime factors
    """
    assert len(p_bits) == len(q_bits), "p and q bits should be of equal length."

    # Big endian to little endian.
    # Also make a copy to ensure we don't modify the original bits.
    p_bits = p_bits[::-1]
    q_bits = q_bits[::-1]
    d_bits = d_bits[::-1]

    # p and q are prime, odd.
    p_bits[0] = 1
    q_bits[0] = 1

    # Because e is small, k can be found by brute force.
    logging.info("Brute forcing k...")
    k, d__bits = _find_k(N, e, d_bits)
    logging.info(f"Found k = {k}")

    _correct_msb(d_bits, d__bits)

    tk = _tau(k)
    _correct_lsb(e, d_bits, 2 + tk)

    logging.info("Computing kp and kq...")
    x = var("x")
    for sol in solve_mod(x ** 2 - x * (k * (N - 1) + 1) - k == 0, e):
        kp = int(sol[0])
        kq = (-pow(kp, -1, e) * k) % e
        logging.info(f"Trying kp = {kp} and kq = {kq}...")

        # Big endian to little endian.
        # Also make a copy for every try of kp and kq so we are sure these bits are not modified.
        # We don't need to make a copy of p, q, and d bits in this loop because those bits only get modified in the branch and prune.
        # The branch and prune algorithm always resets the bits after recursion.
        dp_bits_ = dp_bits[::-1]
        dq_bits_ = dq_bits[::-1]

        tkp = _tau(kp)
        _correct_lsb(e, dp_bits_, 1 + tkp)
        tkq = _tau(kq)
        _correct_lsb(e, dq_bits_, 1 + tkq)

        logging.info("Starting branch and prune algorithm...")
        for p, q in _branch_and_prune_pqddpdq(N, e, k, tk, kp, tkp, kq, tkq, p_bits, q_bits, d_bits, dp_bits_, dq_bits_, 1):
            if p * q == N:
                return int(p), int(q)
