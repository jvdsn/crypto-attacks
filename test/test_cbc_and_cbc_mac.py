import os
import sys
from random import randbytes
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.cbc_and_cbc_mac import eam_key_reuse
from attacks.cbc_and_cbc_mac import etm_key_reuse
from attacks.cbc_and_cbc_mac import mte_key_reuse


class TestCBCAndCBCMAC(TestCase):
    def _encrypt_eam(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = randbytes(16)
        c = AES.new(key, AES.MODE_CBC, iv).encrypt(p)
        # Encrypt-and-MAC using CBC-MAC to prevent chosen-ciphertext attacks.
        t = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        return iv, c, t

    def _decrypt_eam(self, key, iv, c, t):
        p = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        # Check the MAC to be sure the message isn't forged.
        if t != t_:
            return None

        return unpad(p, 16)

    def _encrypt_etm(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = randbytes(16)
        c = AES.new(key, AES.MODE_CBC, iv).encrypt(p)
        # Encrypt-then-MAC using CBC-MAC to prevent chosen-ciphertext attacks.
        t = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(iv + c)[-16:]
        return iv, c, t

    def _decrypt_etm(self, key, iv, c, t):
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(iv + c)[-16:]
        # Check the MAC to be sure the message isn't forged.
        if t != t_:
            return None

        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(c), 16)

    def _encrypted_zeroes(self, key):
        return AES.new(key, AES.MODE_ECB).encrypt(bytes(16))

    def _encrypt_mte(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = randbytes(16)
        # MAC-then-encrypt using CBC-MAC to prevent chosen-ciphertext attacks.
        t = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        c = AES.new(key, AES.MODE_CBC, iv).encrypt(p + t)
        return iv, c

    def _decrypt_mte(self, key, iv, c):
        d = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        p = d[:-16]
        t = d[-16:]
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        # Check the MAC to be sure the message isn't forged.
        if t != t_:
            return None

        return unpad(p, 16)

    def test_eam_key_reuse(self):
        key = randbytes(16)
        for i in range(16):
            p = randbytes(i + 1)
            iv, c, t = self._encrypt_eam(key, p)
            p_ = eam_key_reuse.attack(lambda iv, c, t: self._decrypt_eam(key, iv, c, t), iv, c, t)
            self.assertEqual(p, p_)

    def test_etm_key_reuse(self):
        key = randbytes(16)
        for i in range(16):
            p = randbytes(i + 1)
            iv, c, t = self._encrypt_etm(key, p)
            p_ = etm_key_reuse.attack(lambda p: self._encrypt_etm(key, p), lambda iv, c, t: self._decrypt_etm(key, iv, c, t), iv, c, t)
            self.assertEqual(p, p_)

    def test_mte_key_reuse(self):
        key = randbytes(16)
        encrypted_zeroes = self._encrypted_zeroes(key)
        for i in range(16):
            p = randbytes(i + 1)
            iv, c = self._encrypt_mte(key, p)
            p_ = mte_key_reuse.attack(lambda iv, c: self._decrypt_mte(key, iv, c), iv, c, encrypted_zeroes)
            self.assertEqual(p, p_)
