from unittest import TestCase
from zlib import compress

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


class TestCBC(TestCase):
    from cbc import bit_flipping
    from cbc import iv_recovery
    from cbc import padding_oracle

    def _encrypt(self, key, p):
        iv = get_random_bytes(16)
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        c = cipher.encrypt(p)
        return iv, c

    def _decrypt(self, key, iv, c):
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        p = cipher.decrypt(c)
        return p

    def _valid_padding(self, key, iv, c):
        try:
            cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
            unpad(cipher.decrypt(c), 16)
            return True
        except ValueError:
            return False

    def test_bit_flipping(self):
        key = get_random_bytes(16)
        p = get_random_bytes(32)
        p_ = get_random_bytes(16)
        iv, c = self._encrypt(key, p)

        iv_, c_ = self.bit_flipping.attack(iv, c, 16, p[16:16 + len(p_)], p_)

        p__ = self._decrypt(key, iv_, c_)
        self.assertEqual(p_, p__[16:16 + len(p_)])

    def test_iv_recovery(self):
        key = get_random_bytes(16)
        iv = get_random_bytes(16)

        iv_ = self.iv_recovery.attack(lambda c: self._decrypt(key, iv, c))
        self.assertEqual(iv, iv_)

    def test_padding_oracle(self):
        key = get_random_bytes(16)

        for i in range(16):
            p = pad(get_random_bytes(i + 1), 16)
            iv, c = self._encrypt(key, p)
            p_ = self.padding_oracle.attack(lambda iv, c: self._valid_padding(key, iv, c), iv, c)
            self.assertEqual(p, p_)


class TestCBCAndCBCMAC(TestCase):
    from cbc_and_cbc_mac import eam_key_reuse
    from cbc_and_cbc_mac import etm_key_reuse
    from cbc_and_cbc_mac import mte_key_reuse

    def _encrypt_eam(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = get_random_bytes(16)
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
        iv = get_random_bytes(16)
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
        iv = get_random_bytes(16)
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
        key = get_random_bytes(16)

        for i in range(16):
            p = get_random_bytes(i + 1)
            iv, c, t = self._encrypt_eam(key, p)
            p_ = self.eam_key_reuse.attack(lambda iv, c, t: self._decrypt_eam(key, iv, c, t), iv, c, t)
            self.assertEqual(p, p_)

    def test_etm_key_reuse(self):
        key = get_random_bytes(16)

        for i in range(16):
            p = get_random_bytes(i + 1)
            iv, c, t = self._encrypt_etm(key, p)
            p_ = self.etm_key_reuse.attack(lambda p: self._encrypt_etm(key, p), lambda iv, c, t: self._decrypt_etm(key, iv, c, t), iv, c, t)
            self.assertEqual(p, p_)

    def test_mte_key_reuse(self):
        key = get_random_bytes(16)
        encrypted_zeroes = self._encrypted_zeroes(key)

        for i in range(16):
            p = get_random_bytes(i + 1)
            iv, c = self._encrypt_mte(key, p)
            p_ = self.mte_key_reuse.attack(lambda iv, c: self._decrypt_mte(key, iv, c), iv, c, encrypted_zeroes)
            self.assertEqual(p, p_)


class TestCBCMAC(TestCase):
    from cbc_mac import length_extension

    def _sign(self, key, m):
        return AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(m)[-16:]

    def _verify(self, key, m, t):
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(m)[-16:]
        return t == t_

    def test_length_extension(self):
        key = get_random_bytes(16)
        m1 = get_random_bytes(16)
        t1 = self._sign(key, m1)
        m2 = get_random_bytes(16)
        t2 = self._sign(key, m2)

        m3, t3 = self.length_extension.attack(m1, t1, m2, t2)
        self.assertTrue(self._verify(key, m3, t3))


class TestCTR(TestCase):
    from ctr import crime
    from ctr import separator_oracle

    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(p)

    def _valid_separators(self, separator, separator_count, key, c):
        p = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(c)
        return p.count(separator) == separator_count

    def test_crime(self):
        key = get_random_bytes(16)
        for _ in range(20):
            s = get_random_bytes(16)

            s_ = self.crime.attack(lambda p: self._encrypt(key, compress(p + s)), len(s))
            if s_ == s:
                # CRIME does not work on all secrets.
                break
        else:
            self.fail()

    def test_separator_oracle(self):
        separator = ord("|")
        separator_count = 1
        key = get_random_bytes(16)
        p = get_random_bytes(16)
        for _ in range(separator_count):
            p += bytes([separator]) + get_random_bytes(16)

        c = self._encrypt(key, p)

        p_ = self.separator_oracle.attack(lambda c: self._valid_separators(separator, separator_count, key, c), separator, c)
        self.assertEqual(p, p_)


class TestECB(TestCase):
    from ecb import plaintext_recovery

    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_ECB).encrypt(p)

    def test_plaintext_recovery(self):
        key = get_random_bytes(16)
        s = get_random_bytes(16)

        s_ = self.plaintext_recovery.attack(lambda p: self._encrypt(key, pad(p + s, 16)))
        self.assertEqual(s, s_)
