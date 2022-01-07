from sage.all import is_prime


def _get_possible_primes(e, d):
    mul = e * d - 1
    for k in range(3, e):
        if mul % k == 0:
            p = (mul // k) + 1
            if is_prime(p):
                yield p


def attack(e_start, e_end, N=None, dp=None, dq=None, p_bitsize=None, q_bitsize=None):
    """
    Generates possible prime factors for a modulus, if d_p and/or d_q are known.
    More information: Campagna M., Sethi A., "Key Recovery Method for CRT Implementation of RSA"
    :param e_start: the start value of the public exponent (inclusive)
    :param e_end: the end value of the public exponent (exclusive)
    :param N: the modulus, will be used to check the factors if not None (default: None)
    :param dp: the d exponent for p, will be used to generate possible factors for p if not None (default: None)
    :param dq: the d exponent for q, will be used to generate possible factors for q if not None (default: None)
    :param p_bitsize: the amount of bits of p, will be used to check possible factors for p if not None (default: None)
    :param q_bitsize: the amount of bits of q, will be used to check possible factors for q if not None (default: None)
    :return: a generator generating tuples containing possible prime factors
    """
    assert not (dp is None and dq is None), "At least one of the CRT private exponents should be known."

    if dp is not None and dq is not None:
        for e in range(e_start, e_end, 2):
            for p in _get_possible_primes(e, dp):
                for q in _get_possible_primes(e, dq):
                    if (N is None or p * q == N) and (p_bitsize is None or p.bit_length() == p_bitsize) and (q_bitsize is None or q.bit_length() == q_bitsize):
                        yield p, q

        return

    if dp is not None:
        for e in range(e_start, e_end, 2):
            for p in _get_possible_primes(e, dp):
                if p_bitsize is None or p.bit_length() == p_bitsize:
                    if N is None:
                        yield p
                    elif N % p == 0:
                        yield p, N // p

        return

    if dq is not None:
        for e in range(e_start, e_end, 2):
            for q in _get_possible_primes(e, dq):
                if q_bitsize is None or q.bit_length() == q_bitsize:
                    if N is None:
                        yield q
                    elif N % q == 0:
                        yield q, N // q

        return
