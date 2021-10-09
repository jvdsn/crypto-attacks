import os
import sys
from random import getrandbits
from random import randint
from unittest import TestCase

from sage.all import EllipticCurve
from sage.all import GF

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.ecc import ecdsa_nonce_reuse
from attacks.ecc import parameter_recovery
from attacks.ecc import singular_curve
from attacks.ecc import smart_attack


class TestECC(TestCase):
    _O = "origin"

    def _negation(self, p, P):
        if P == self._O:
            return P

        return P[0], -P[1] % p

    def _add(self, p, a2, a4, P1, P2):
        if P1 == self._O:
            return P2

        if P2 == self._O:
            return P1

        if P1 == self._negation(p, P2):
            return self._O

        if P1 == P2:
            gradient = (3 * P1[0] ** 2 + 2 * a2 * P1[0] + a4) * pow(2 * P1[1], -1, p) % p
        else:
            gradient = (P2[1] - P1[1]) * pow(P2[0] - P1[0], -1, p) % p

        x = (gradient ** 2 - a2 - P1[0] - P2[0]) % p
        y = (gradient * (P1[0] - x) - P1[1]) % p
        return x, y

    def _double_and_add(self, p, a2, a4, G, l):
        multiplication_result = self._O
        double = G
        while l > 0:
            if l % 2 == 1:
                multiplication_result = self._add(p, a2, a4, multiplication_result, double)

            double = self._add(p, a2, a4, double, double)
            l //= 2

        return multiplication_result

    def test_ecdsa_nonce_reuse(self):
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
        b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        p_256 = EllipticCurve(GF(p), [a, b])
        gen = p_256.gen(0)
        n = int(gen.order())
        x = randint(1, n - 1)
        k = randint(1, n - 1)
        r = int((k * gen).xy()[0])
        m1 = getrandbits(n.bit_length())
        s1 = pow(k, -1, n) * (m1 + r * x) % n
        m2 = getrandbits(n.bit_length())
        s2 = pow(k, -1, n) * (m2 + r * x) % n
        for k_, x_ in ecdsa_nonce_reuse.attack(n, m1, r, s1, m2, r, s2):
            self.assertIsInstance(k_, int)
            self.assertIsInstance(x_, int)
            if k_ == k and x_ == x:
                break
        else:
            self.fail()

    def test_frey_ruck_attack(self):
        # TODO: Frey-Ruck attack is too inconsistent in unit tests.
        pass

    def test_mov_attack(self):
        # TODO: MOV attack is too inconsistent in unit tests.
        pass

    def test_parameter_recovery(self):
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
        b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        p_256 = EllipticCurve(GF(p), [a, b])
        x1, y1 = p_256.random_point().xy()
        x2, y2 = p_256.random_point().xy()
        a_, b_ = parameter_recovery.attack(p, x1, y1, x2, y2)
        self.assertIsInstance(a_, int)
        self.assertIsInstance(b_, int)
        self.assertEqual(a, a_)
        self.assertEqual(b, b_)

    def test_singular_curve(self):
        # Singular point is a cusp.
        p = 29800669538070463271
        a2 = 9813480773723366080
        a4 = 13586186857864981308
        a6 = 18910877985247806581
        Gx = 13284247619583658910
        Gy = 3629049282720081919
        # We don't know the order of the base point, so we keep l pretty low to make sure we don't exceed it.
        l = randint(1, 4096)
        Px, Py = self._double_and_add(p, a2, a4, (Gx, Gy), l)
        l_ = singular_curve.attack(p, a2, a4, a6, Gx, Gy, Px, Py)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        # Singular point is a node.
        p = 29800669538070463271
        a2 = 13753215131529770662
        a4 = 16713139382466325228
        a6 = 19476075514740408653
        Gx = 16369123140759309684
        Gy = 5098114980663762719
        # We don't know the order of the base point, so we keep l pretty low to make sure we don't exceed it.
        l = randint(1, 4096)
        Px, Py = self._double_and_add(p, a2, a4, (Gx, Gy), l)
        l_ = singular_curve.attack(p, a2, a4, a6, Gx, Gy, Px, Py)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

    def test_smart_attack(self):
        E = EllipticCurve(GF(23304725718649417969), [8820341459377516260, 5880227639585010840])
        G = E.gen(0)
        n = int(G.order())
        l = randint(1, n - 1)
        l_ = smart_attack.attack(G, l * G)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)
