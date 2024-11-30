import os
import sys
from random import getrandbits
from random import randrange
from unittest import TestCase

from sage.all import EllipticCurve
from sage.all import GF

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.ecc import ecdsa_nonce_reuse
from attacks.ecc import frey_ruck_attack
from attacks.ecc import mov_attack
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
        G = p_256.gen(0)
        n = int(G.order())
        x = randrange(1, n)
        k = randrange(1, n)
        r = int((k * G).xy()[0])
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
        p = 23305425500899
        a = 13079575536215
        b = 951241857177
        l = 709658
        E = EllipticCurve(GF(p), [a, b])
        P = E(17662927853004, 1766549410280)
        R = E(2072411881257, 5560421985272)
        l_ = frey_ruck_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 93340306032025588917032364977153
        a = 71235469403697021051902688366816
        b = 47490312935798014034601792244544
        l = 764009
        E = EllipticCurve(GF(p), [a, b])
        P = E(10362409929965041614317835692463, 79529049191468905652172306035573)
        R = E(15411349585423321468944221089888, 9416052907883278088782335830033)
        l_ = frey_ruck_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 23305425500899
        a = 1
        b = 0
        l = 4500974
        E = EllipticCurve(GF(p), [a, b])
        P = E(18414716422748, 9607997424906)
        R = E(22829488331658, 15463570264423)
        l_ = frey_ruck_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 625276251724681468065787127391468008213949163
        a = 625276251724681468065787127391468008213949162
        b = 0
        l = 573267844
        E = EllipticCurve(GF(p), [a, b])
        P = E(106475251480616516532312035568555890205578047, 431897649280430503785680130194791468278435206)
        R = E(325210632278386769754263691768220745652895158, 308687159471094662490925278095484225164835682)
        l_ = frey_ruck_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 1527181879
        a = 623779536
        b = 170102
        l = 16029094
        E = EllipticCurve(GF(p), [a, b])
        P = E(470008538, 130171157)
        R = E(1247215477, 775699526)
        l_ = frey_ruck_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

    def test_mov_attack(self):
        p = 23305425500899
        a = 13079575536215
        b = 951241857177
        l = 709658
        E = EllipticCurve(GF(p), [a, b])
        P = E(17662927853004, 1766549410280)
        R = E(2072411881257, 5560421985272)
        l_ = mov_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 93340306032025588917032364977153
        a = 71235469403697021051902688366816
        b = 47490312935798014034601792244544
        l = 764009
        E = EllipticCurve(GF(p), [a, b])
        P = E(10362409929965041614317835692463, 79529049191468905652172306035573)
        R = E(15411349585423321468944221089888, 9416052907883278088782335830033)
        l_ = mov_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 23305425500899
        a = 1
        b = 0
        l = 4500974
        E = EllipticCurve(GF(p), [a, b])
        P = E(18414716422748, 9607997424906)
        R = E(22829488331658, 15463570264423)
        l_ = mov_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 625276251724681468065787127391468008213949163
        a = 625276251724681468065787127391468008213949162
        b = 0
        l = 573267844
        E = EllipticCurve(GF(p), [a, b])
        P = E(106475251480616516532312035568555890205578047, 431897649280430503785680130194791468278435206)
        R = E(325210632278386769754263691768220745652895158, 308687159471094662490925278095484225164835682)
        l_ = mov_attack.attack(P, R)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        p = 1527181879
        a = 623779536
        b = 170102
        l = 16029094
        E = EllipticCurve(GF(p), [a, b])
        P = E(470008538, 130171157)
        R = E(1247215477, 775699526)
        l_ = mov_attack.attack(P, R)
        self.assertIsNone(l_)

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
        l = randrange(1, 4096)
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
        l = randrange(1, 4096)
        Px, Py = self._double_and_add(p, a2, a4, (Gx, Gy), l)
        l_ = singular_curve.attack(p, a2, a4, a6, Gx, Gy, Px, Py)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

    def test_smart_attack(self):
        F = GF(23304725718649417969)
        E = EllipticCurve(F, [8820341459377516260, 5880227639585010840])
        G = E.gen(0)
        l = randrange(1, G.order())
        l_ = smart_attack.attack(G, l * G)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        F = GF(11 ** 2)
        g = F.gen()
        E = EllipticCurve(F, [g, 8 * g])
        G = E.gen(0)
        for l in range(1, G.order()):
            l_ = smart_attack.attack(G, l * G)
            self.assertIsInstance(l_, int)
            self.assertEqual(l, l_)

        F = GF(13 ** 3)
        g = F.gen()
        E = EllipticCurve(F, [g ** 2, g ** 2 + 9 * g + 8])
        G = E.gen(0)
        for l in range(1, G.order()):
            l_ = smart_attack.attack(G, l * G)

        F = GF(17 ** 4)
        g = F.gen()
        E = EllipticCurve(F, [13 * g ** 3 + 5 * g ** 2 + 12 * g + 9, g ** 3 + g ** 2 + 9 * g + 11])
        G = E.gen(0)
        l = randrange(1, G.order())
        l_ = smart_attack.attack(G, l * G)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)
