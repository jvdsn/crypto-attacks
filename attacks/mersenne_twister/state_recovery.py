import os
import sys

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks import mersenne_twister


def _reverse_left(y, shift, mask, w):
    y_ = 0
    for i in range(shift, w, shift):
        m = 2 ** i - 1
        y_ = (y ^ ((y_ << shift) & mask)) & m
    y_ = (y ^ ((y_ << shift) & mask)) & (2 ** w - 1)
    return y_


def _reverse_right(y, shift, mask, w):
    y_ = 0
    for i in range(shift, w, shift):
        m = (2 ** i - 1) << (w - i)
        y_ = (y ^ ((y_ >> shift) & mask)) & m
    y_ = (y ^ ((y_ >> shift) & mask)) & (2 ** w - 1)
    return y_


def _attack_mt(y, mt):
    assert len(y) == mt.n
    mt.index = 0
    while mt.index < mt.n:
        yi = y[mt.index]
        yi = _reverse_right(yi, mt.l, 2 ** mt.w - 1, mt.w)
        yi = _reverse_left(yi, mt.t, mt.c, mt.w)
        yi = _reverse_left(yi, mt.s, mt.b, mt.w)
        yi = _reverse_right(yi, mt.u, mt.d, mt.w)
        mt.mt[mt.index] = yi
        mt.index += 1
    return mt


def attack(y, w, n, m, r, a, b, c, s, t, u, d, l):
    """
    Recovers the state from a Mersenne Twister instance using n outputs.
    No twist should have been performed during the outputs.
    :param y: the outputs (must be of length n)
    :param w: the parameter w
    :param n: the parameter n
    :param m: the parameter m
    :param r: the parameter r
    :param a: the parameter a
    :param b: the parameter b
    :param c: the parameter c
    :param s: the parameter s
    :param t: the parameter t
    :param u: the parameter u
    :param d: the parameter d
    :param l: the parameter l
    :return: a cloned Mersenne Twister instance
    """
    return _attack_mt(y, mersenne_twister.MersenneTwister(w, n, m, r, a, b, c, s, t, u, d, l))


def attack_mt19937(y):
    """
    Recovers the state from an MT19937 instance using 624 outputs.
    No twist should have been performed during the outputs.
    :param y: the outputs
    :return: a cloned MT19937 instance
    """
    return _attack_mt(y, mersenne_twister.mt19937())


def attack_mt19937_64(y):
    """
    Recovers the state from an MT19937-64 instance using 312 outputs.
    No twist should have been performed during the outputs.
    :param y: the outputs
    :return: a cloned MT19937-64 instance
    """
    return _attack_mt(y, mersenne_twister.mt19937_64())
