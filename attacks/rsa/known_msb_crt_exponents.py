from sage.all import PolynomialRing, GF, Zmod, gcd, ceil, is_prime

def attack(e, N, dp_msb, dq_msb, dp_msb_bit_length, dq_msb_bit_length, delta_upper_bound):
    """
    Generates prime factors for a modulus, if the MSB of dp and dq are known.
    More information: Alexander M., Julian N., Santanu S., "Approximate Divisor Multiples - Factoring with Only a Third of the Secret CRT-Exponents"
    :param e: public exponent
    :param N: public modulus
    :param dp_msb: most significant bits (MSB) of d mod p - 1 
    :param dq_msb: most significant bits (MSB) of q mod p - 1 
    :param dp_msb_bit_length: the bit length of dp_msb
    :param dq_msb_bit_length: the bit length of dq_msb
    :param delta_upper_bound: upper bound of delta, defined below
    :return: the prime factors of N = p * q
    
    Constraints:
    - We will set the public exponent bit length (e) as log2(N) * alpha, where 0 < alpha < 1
    - Then, the unknown LSBs of dp and dq are upper bound in bit length by log2(N) * delta
    - delta < (1/2) - 2 * alpha
    """
    
    # https://stackoverflow.com/questions/14822184/is-there-a-ceiling-equivalent-of-operator-in-python
    A_hat = -(2**(dp_msb_bit_length + dq_msb_bit_length) * e**2 * dp_msb * dq_msb // -N) # A_hat = kl
    
    x, = GF(e)["x"].gens()
    poly = x**2 - (1 - A_hat*(N - 1)) * x + A_hat
   
    k_roots = poly.roots()
    
    for root in k_roots:
        k = int(root[0])
        a = (e * dp_msb * 2**dp_msb_bit_length + k - 1) * pow(e, -1, k * N) % (k * N)

        dp_lsb, = Zmod(k * N)["dp_lsb"].gens()
        poly = dp_lsb + a

        dp_roots = poly.small_roots(X = 2**dp_msb_bit_length, beta = delta_upper_bound)
        print(dp_roots)
        if dp_roots:
            dp = int(dp_roots[0]) + a
            p = int(gcd(dp, N))
            q = N // p

            assert N == p * q
            return p, q
    
    return "Attack failed, make sure that your params satisfies the constraints."