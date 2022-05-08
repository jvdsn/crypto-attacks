import os
import sys
from random import getrandbits
from random import randrange
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.hnp import extended_hnp
from attacks.hnp import lattice_attack
from shared.partial_integer import PartialInteger


class TestHNP(TestCase):
    def _dsa(self, p, g, x):
        h = getrandbits(p.bit_length())
        k = randrange(1, p)
        r = pow(g, k, p)
        s = (pow(k, -1, p) * (h + x * r)) % p
        return h, r, s, k

    def test_extended_hnp(self):
        # Not a safe prime, but it doesn't really matter.
        p = 299182277398782807472682876223275635417
        g = 5
        x = randrange(1, p)

        k_bit_length = p.bit_length()
        lsb_unknown = 50
        msb_unknown = 50
        n_signatures = 5
        h = []
        r = []
        s = []
        k = []
        partial_k = []
        for i in range(n_signatures):
            hi, ri, si, ki = self._dsa(p, g, x)
            h.append(hi)
            r.append(ri)
            s.append(si)
            k.append(ki)
            partial_k.append(PartialInteger.middle_of(ki, k_bit_length, lsb_unknown, msb_unknown))

        x_ = next(extended_hnp.dsa_known_bits(p, h, r, s, PartialInteger.unknown(k_bit_length), partial_k))
        self.assertIsInstance(x_, int)
        self.assertEqual(x, x_)

    def test_lattice_attack(self):
        # Not a safe prime, but it doesn't really matter.
        p = 299182277398782807472682876223275635417
        g = 5
        x = randrange(1, p)

        k_bit_length = p.bit_length()
        msb_known = 7
        n_signatures = 25
        h = []
        r = []
        s = []
        k = []
        partial_k = []
        for i in range(n_signatures):
            hi, ri, si, ki = self._dsa(p, g, x)
            h.append(hi)
            r.append(ri)
            s.append(si)
            k.append(ki)
            partial_k.append(PartialInteger.msb_of(ki, k_bit_length, msb_known))

        x_, k_ = next(lattice_attack.dsa_known_msb(p, h, r, s, partial_k))
        self.assertIsInstance(x_, int)
        self.assertIsInstance(k_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(k_[i], int)
            self.assertEqual(k[i], k_[i])

        k_bit_length = p.bit_length()
        lsb_known = 7
        n_signatures = 25
        h = []
        r = []
        s = []
        k = []
        partial_k = []
        for i in range(n_signatures):
            hi, ri, si, ki = self._dsa(p, g, x)
            h.append(hi)
            r.append(ri)
            s.append(si)
            k.append(ki)
            partial_k.append(PartialInteger.lsb_of(ki, k_bit_length, lsb_known))

        x_, k_ = next(lattice_attack.dsa_known_lsb(p, h, r, s, partial_k))
        self.assertIsInstance(x_, int)
        self.assertIsInstance(k_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(k_[i], int)
            self.assertEqual(k[i], k_[i])

        k_bit_length = p.bit_length()
        lsb_unknown = 20
        msb_unknown = 10
        h1, r1, s1, k1 = self._dsa(p, g, x)
        partial_k1 = PartialInteger.middle_of(k1, k_bit_length, lsb_unknown, msb_unknown)
        h2, r2, s2, k2 = self._dsa(p, g, x)
        partial_k2 = PartialInteger.middle_of(k2, k_bit_length, lsb_unknown, msb_unknown)

        x_, k1_, k2_ = lattice_attack.dsa_known_middle(p, h1, r1, s1, partial_k1, h2, r2, s2, partial_k2)
        self.assertIsInstance(x_, int)
        self.assertIsInstance(k1_, int)
        self.assertIsInstance(k2_, int)
        self.assertEqual(x, x_)
        self.assertEqual(k1, k1_)
        self.assertEqual(k2, k2_)
