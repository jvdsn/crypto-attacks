from Crypto.Util.number import isPrime


def _get_possible_primes(e, d):
    mul = e * d - 1
    for k in range(3, e):
        if mul % k == 0:
            p = (mul // k) + 1
            if isPrime(p):
                yield p


def factorize(e_start, e_end, n=None, dp=None, dq=None, p_bitsize=None, q_bitsize=None):
    """
    Factorizes a known modulus, or returns possible primes, if d_p and/or d_q are known.
    More information: Campagna M., Sethi A., "Key Recovery Method for CRT Implementation of RSA"
    :param e_start: the start value of the public exponent (inclusive)
    :param e_end: the end value of the public exponent (exclusive)
    :param n: the modulus, will be used to check the factors if not None (default: None)
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
                    if (n is None or p * q == n) and (p_bitsize is None or p.bit_length() == p_bitsize) and (q_bitsize is None or q.bit_length() == q_bitsize):
                        yield p, q

        return

    if dp is not None:
        for e in range(e_start, e_end, 2):
            for p in _get_possible_primes(e, dp):
                if p_bitsize is None or p.bit_length() == p_bitsize:
                    if n is None:
                        yield p
                    elif n % p == 0:
                        yield p, n // p

        return

    if dq is not None:
        for e in range(e_start, e_end, 2):
            for q in _get_possible_primes(e, dq):
                if q_bitsize is None or q.bit_length() == q_bitsize:
                    if n is None:
                        yield q
                    elif n % q == 0:
                        yield q, n // q

        return

# for p in factorize(65537, 65538, None, 0x878f7c1b9b19b1693c1371305f194cd08c770c8f5976b2d8e3cf769a1117080d6e90a10aef9da6eb5b34219b71f4c8e5cde3a9d36945ac507ee6dfe4c146e7458ef83fa065e3036e5fbf15597e97a7ba93a31124d97c177e68e38adc4c45858417abf8034745d6b3782a195e6dd3cf0be14f5d97247900e9aac3b2b5a89f33a3f8f71d27d670401ca185eb9c88644b7985e4d98a7da37bfffdb737e54b6e0de2004d0c8c425fb16380431d7de40540c02346c98991b748ebbc8aac73dd58de6f7ff00a302f4047020b6cd9098f6ba686994f5e043e7181edfc552e18bce42b3a42b63f7ccb7729b74e76a040055d397278cb939240f236d0a2a79757ba7a9f09, None, 2048, None):
#     print(p)
