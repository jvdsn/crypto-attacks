import os
import sys
from random import getrandbits
from random import randint
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.hnp import lattice_attack


class TestHNP(TestCase):
    def _dsa(self, p, g, x):
        h = getrandbits(p.bit_length())
        k = randint(1, p - 1)
        r = pow(g, k, p)
        s = (pow(k, -1, p) * (h + x * r)) % p
        return h, r, s, k

    def test_lattice_attack(self):
        # Not a safe prime, but it doesn't really matter.
        p = 299182277398782807472682876223275635417
        g = 5
        x = randint(1, p - 1)

        nonce_bitsize = p.bit_length()
        msb_known = 7
        n_signatures = 25
        nonces = []
        signatures = []
        for i in range(n_signatures):
            h, r, s, k = self._dsa(p, g, x)
            nonces.append(k)
            signatures.append((h, r, s, k >> (nonce_bitsize - msb_known)))

        x_, nonces_ = next(lattice_attack.dsa_known_msb(p, signatures, nonce_bitsize, msb_known))
        self.assertIsInstance(x_, int)
        self.assertIsInstance(nonces_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(nonces_[i], int)
            self.assertEqual(nonces[i], nonces_[i])

        nonce_bitsize = p.bit_length()
        lsb_known = 7
        n_signatures = 25
        nonces = []
        signatures = []
        for i in range(n_signatures):
            h, r, s, k = self._dsa(p, g, x)
            nonces.append(k)
            signatures.append((h, r, s, k % (2 ** lsb_known)))

        x_, nonces_ = next(lattice_attack.dsa_known_lsb(p, signatures, nonce_bitsize, lsb_known))
        self.assertIsInstance(x_, int)
        self.assertIsInstance(nonces_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(nonces_[i], int)
            self.assertEqual(nonces[i], nonces_[i])

        nonce_bitsize = p.bit_length()
        msb_unknown = 10
        lsb_unknown = 20
        h1, r1, s1, k1 = self._dsa(p, g, x)
        signature1 = (h1, r1, s1, (k1 >> lsb_unknown) % (2 ** (nonce_bitsize - msb_unknown)))
        h2, r2, s2, k2 = self._dsa(p, g, x)
        signature2 = (h2, r2, s2, (k2 >> lsb_unknown) % (2 ** (nonce_bitsize - msb_unknown)))

        x_, k1_, k2_ = lattice_attack.dsa_known_middle(p, signature1, signature2, nonce_bitsize, msb_unknown, lsb_unknown)
        self.assertIsInstance(x_, int)
        self.assertIsInstance(k1_, int)
        self.assertIsInstance(k2_, int)
        self.assertEqual(x, x_)
        self.assertEqual(k1, k1_)
        self.assertEqual(k2, k2_)
