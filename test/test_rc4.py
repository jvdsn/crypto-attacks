import os
import sys
from unittest import TestCase

from Crypto.Cipher import ARC4

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.rc4 import fms


class TestRC4(TestCase):
    def _encrypt(self, iv, key, p):
        return ARC4.new(iv + key).encrypt(p)

    def test_fms(self):
        keys = [
            "3718f3809a",
            "7e2160f62e99",
            "be0718252b4fbc",
            "6463c171f7391d30",
            "36a05ac48cd2900621",
            "6a72ef3705600df0e025",
            "47bf390c9573cf4b5d4c18",
            "84be086db8ba1306f6f4b302",
            "08e3ac0eb6a483095f92ad6ed1",
            "6c13bde5d8cc704045727cf54d36",
            "9a1c69c725ddc2d6d5bf0b7853393b",
            "70509f20bd38c202eecbbcec070161dd",
            "3558cf4e33164375994664286941b5aae7",
            "4b37460ddb71f90dfc4b26a9e816ad49beda",
            "ca78c64d55e0a2add6625474f7334123a0b59b",
            "8ff7efb0a9034d227890e87b1baf07ec3021e797",
            "3a7b8d4facc69e982a5c70d179e15a75087a9add53",
            "820297475275fca9d8d07939e2ddd76b508432f140b4",
            "b2b3e47e81276906491c30d42f9a9ae7daee633d6a2464",
            "1eba58bbb83e4f48d3395d9ddf50b50bd797fb230877b0b1",
            "1b0339415ef65082bd2040167ab4320c7e11dc1493854faa39",
            "966c7fd547317db5a11e1a6cd4b7e17ca36dc942fe961888c381",
            "ac87f9eae75e978e6c097b31423e2c522e4232b7f0a3f58db407f1",
        ]

        for key in keys:
            key = bytearray.fromhex(key)
            key_ = fms.attack(lambda iv, p: self._encrypt(iv, key, p), len(key))
            self.assertEqual(key, key_)
