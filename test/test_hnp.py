import os
import sys
from random import getrandbits
from random import randrange
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.hnp import lattice_attack
from shared.partial_integer import PartialInteger


class TestHNP(TestCase):
    def _dsa(self, p, g, x):
        h = getrandbits(p.bit_length())
        k = randrange(1, p)
        r = pow(g, k, p)
        s = (pow(k, -1, p) * (h + x * r)) % p
        return h, r, s, k

    def test_lattice_attack(self):
        # Not a safe prime, but it doesn't really matter.
        p = 299182277398782807472682876223275635417
        g = 5
        x = randrange(1, p)

        nonce_bit_length = p.bit_length()
        msb_known = 7
        n_signatures = 25
        nonces = []
        signatures = []
        partial_nonces = []
        for i in range(n_signatures):
            h, r, s, k = self._dsa(p, g, x)
            nonces.append(k)
            signatures.append((h, r, s))
            partial_nonces.append(PartialInteger.msb_of(k, nonce_bit_length, msb_known))

        x_, nonces_ = next(lattice_attack.dsa_known_msb(p, signatures, partial_nonces))
        self.assertIsInstance(x_, int)
        self.assertIsInstance(nonces_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(nonces_[i], int)
            self.assertEqual(nonces[i], nonces_[i])

        nonce_bit_length = p.bit_length()
        lsb_known = 7
        n_signatures = 25
        nonces = []
        signatures = []
        partial_nonces = []
        for i in range(n_signatures):
            h, r, s, k = self._dsa(p, g, x)
            nonces.append(k)
            signatures.append((h, r, s))
            partial_nonces.append(PartialInteger.lsb_of(k, nonce_bit_length, lsb_known))

        x_, nonces_ = next(lattice_attack.dsa_known_lsb(p, signatures, partial_nonces))
        self.assertIsInstance(x_, int)
        self.assertIsInstance(nonces_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(nonces_[i], int)
            self.assertEqual(nonces[i], nonces_[i])

        nonce_bit_length = p.bit_length()
        lsb_unknown = 20
        msb_unknown = 10
        middle_known = nonce_bit_length - lsb_unknown - msb_unknown
        h1, r1, s1, k1 = self._dsa(p, g, x)
        signature1 = (h1, r1, s1)
        partial_nonce1 = PartialInteger.middle_of(k1, middle_known, lsb_unknown, msb_unknown)
        h2, r2, s2, k2 = self._dsa(p, g, x)
        signature2 = (h2, r2, s2)
        partial_nonce2 = PartialInteger.middle_of(k2, middle_known, lsb_unknown, msb_unknown)

        x_, k1_, k2_ = lattice_attack.dsa_known_middle(p, signature1, partial_nonce1, signature2, partial_nonce2)
        self.assertIsInstance(x_, int)
        self.assertIsInstance(k1_, int)
        self.assertIsInstance(k2_, int)
        self.assertEqual(x, x_)
        self.assertEqual(k1, k1_)
        self.assertEqual(k2, k2_)
