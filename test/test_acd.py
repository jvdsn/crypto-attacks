import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.acd import mp
from attacks.acd import ol
from attacks.acd import sda


class TestACD(TestCase):
    def test_mp(self):
        p = 13845249886873428613
        N = 217407154917807470895390029782610665191
        a = [217533070209246692596654921907507416418, 204580044578352963965866243184761160753, 140701572771317740546493579818249256489, 204965623030303278851699918560590728481]
        r = [-4487, -10300, -10075, 23477]
        rho = 16
        p_, r_ = mp.attack(N, a, rho)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        for i in range(len(r)):
            self.assertIsInstance(r_[i], int)
            self.assertEqual(r[i], r_[i])

        p = 4238219929
        N = 169749234656568819546953289884491257755
        a = [244914656571365600647675250712402894810, 258938327120706515107425576685234055392, 304762109988168193461144822345045328384, 331420653433993738593271242794196239800, 213192828695455264854663438180715919066, 178555459224222734102095815362417919512, 240756376346047770614611034188210416410, 168622111253832154566397598758889653217]
        r = [48611, 26045, -62765, -18028, -9003, -23809, -42845, -45828]
        rho = 16
        p_, r_ = mp.attack(N, a, rho)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        for i in range(len(r)):
            self.assertIsInstance(r_[i], int)
            self.assertEqual(r[i], r_[i])

    def test_ol(self):
        p = 13845249886873428613
        x = [217533070209246692596654921907507416418, 204580044578352963965866243184761160753, 140701572771317740546493579818249256489, 204965623030303278851699918560590728481]
        r = [-4487, -10300, -10075, 23477]
        rho = 16
        p_, r_ = ol.attack(x, rho)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        for i in range(len(r)):
            self.assertIsInstance(r_[i], int)
            self.assertEqual(r[i], r_[i])

        p = 4238219929
        x = [244914656571365600647675250712402894810, 258938327120706515107425576685234055392, 304762109988168193461144822345045328384, 331420653433993738593271242794196239800, 213192828695455264854663438180715919066, 178555459224222734102095815362417919512, 240756376346047770614611034188210416410, 168622111253832154566397598758889653217]
        r = [48611, 26045, -62765, -18028, -9003, -23809, -42845, -45828]
        rho = 16
        p_, r_ = ol.attack(x, rho)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        for i in range(len(r)):
            self.assertIsInstance(r_[i], int)
            self.assertEqual(r[i], r_[i])

    def test_sda(self):
        p = 13845249886873428613
        x = [217533070209246692596654921907507416418, 204580044578352963965866243184761160753, 140701572771317740546493579818249256489, 204965623030303278851699918560590728481]
        r = [-4487, -10300, -10075, 23477]
        rho = 16
        p_, r_ = sda.attack(x, rho)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        for i in range(len(r)):
            self.assertIsInstance(r_[i], int)
            self.assertEqual(r[i], r_[i])

        p = 4238219929
        x = [244914656571365600647675250712402894810, 258938327120706515107425576685234055392, 304762109988168193461144822345045328384, 331420653433993738593271242794196239800, 213192828695455264854663438180715919066, 178555459224222734102095815362417919512, 240756376346047770614611034188210416410, 168622111253832154566397598758889653217]
        r = [48611, 26045, -62765, -18028, -9003, -23809, -42845, -45828]
        rho = 16
        p_, r_ = sda.attack(x, rho)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        for i in range(len(r)):
            self.assertIsInstance(r_[i], int)
            self.assertEqual(r[i], r_[i])
