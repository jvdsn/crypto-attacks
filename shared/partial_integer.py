from math import log2


class PartialInteger:
    """
    Represents positive integers with some known and some unknown bits.
    """

    def __init__(self):
        """
        Constructs a new PartialInteger with total bit length 0 and no components.
        """
        self.bit_length = 0
        self.unknowns = 0
        self._components = []

    def add_known(self, value, bit_length):
        """
        Adds a known component to the msb of this PartialInteger.
        :param value: the value of the component
        :param bit_length: the bit length of the component
        :return: this PartialInteger, with the component added to the msb
        """
        self.bit_length += bit_length
        self._components.append((value, bit_length))
        return self

    def add_unknown(self, bit_length):
        """
        Adds an unknown component to the msb of this PartialInteger.
        :param bit_length: the bit length of the component
        :return: this PartialInteger, with the component added to the msb
        """
        self.bit_length += bit_length
        self.unknowns += 1
        self._components.append((None, bit_length))
        return self

    def get_known_lsb(self):
        """
        Returns all known lsb in this PartialInteger.
        This method can cross multiple known components, but stops once an unknown component is encountered.
        :return: a tuple containing the known lsb and the bit length of the known lsb
        """
        lsb = 0
        lsb_bit_length = 0
        for value, bit_length in self._components:
            if value is None:
                return lsb, lsb_bit_length

            lsb = lsb + (value << lsb_bit_length)
            lsb_bit_length += bit_length

        return lsb, lsb_bit_length

    def get_known_msb(self):
        """
        Returns all known msb in this PartialInteger.
        This method can cross multiple known components, but stops once an unknown component is encountered.
        :return: a tuple containing the known msb and the bit length of the known msb
        """
        msb = 0
        msb_bit_length = 0
        for value, bit_length in reversed(self._components):
            if value is None:
                return msb, msb_bit_length

            msb = (msb << bit_length) + value
            msb_bit_length += bit_length

        return msb, msb_bit_length

    def get_known_middle(self):
        """
        Returns all known middle bits in this PartialInteger.
        This method can cross multiple known components, but stops once an unknown component is encountered.
        :return: a tuple containing the known middle bits and the bit length of the known middle bits
        """
        middle = 0
        middle_bit_length = 0
        for value, bit_length in self._components:
            if value is None:
                if middle_bit_length > 0:
                    return middle, middle_bit_length
            else:
                middle = middle + (value << middle_bit_length)
                middle_bit_length += bit_length

        return middle, middle_bit_length

    def get_unknown_lsb(self):
        """
        Returns the bit length of the unknown lsb in this PartialInteger.
        This method can cross multiple unknown components, but stops once a known component is encountered.
        :return: the bit length of the unknown lsb
        """
        lsb_bit_length = 0
        for value, bit_length in self._components:
            if value is not None:
                return lsb_bit_length

            lsb_bit_length += bit_length

        return lsb_bit_length

    def get_unknown_msb(self):
        """
        Returns the bit length of the unknown msb in this PartialInteger.
        This method can cross multiple unknown components, but stops once a known component is encountered.
        :return: the bit length of the unknown msb
        """
        msb_bit_length = 0
        for value, bit_length in reversed(self._components):
            if value is not None:
                return msb_bit_length

            msb_bit_length += bit_length

        return msb_bit_length

    def get_unknown_middle(self):
        """
        Returns the bit length of the unknown middle bits in this PartialInteger.
        This method can cross multiple unknown components, but stops once a known component is encountered.
        :return: the bit length of the unknown middle bits
        """
        middle_bit_length = 0
        for value, bit_length in self._components:
            if value is None:
                if middle_bit_length > 0:
                    return middle_bit_length
            else:
                middle_bit_length += bit_length

        return middle_bit_length

    def matches(self, i):
        """
        Returns whether this PartialInteger matches an integer, that is, all known bits are equal.
        :param i: the integer
        :return: True if this PartialInteger matches i, False otherwise
        """
        shift = 0
        for value, bit_length in self._components:
            if value is not None and (i >> shift) % (2 ** bit_length) != value:
                return False

            shift += bit_length

        return True

    def sub(self, unknowns):
        """
        Substitutes some values for the unknown components in this PartialInteger.
        These values can be symbolic (e.g. Sage variables)
        :param unknowns: the unknowns
        :return: an integer or expression with the unknowns substituted
        """
        assert len(unknowns) == self.unknowns
        i = 0
        j = 0
        shift = 0
        for value, bit_length in self._components:
            if value is None:
                # We don't shift here because the unknown could be a symbolic variable
                i += 2 ** shift * unknowns[j]
                j += 1
            else:
                i += value << shift

            shift += bit_length

        return i

    def get_known_and_unknowns(self):
        """
        Returns i_, o, and l such that this integer i = i_ + sum(2^(o_j) * i_j) with i_j < 2^(l_j).
        :return: a tuple of i_, o, and l
        """
        i_ = 0
        o = []
        l = []
        offset = 0
        for value, bit_length in self._components:
            if value is None:
                o.append(offset)
                l.append(bit_length)
            else:
                i_ += 2 ** offset * value

            offset += bit_length

        return i_, o, l

    def get_unknown_bounds(self):
        """
        Returns a list of bounds on each of the unknowns in this PartialInteger.
        A bound is simply 2^l with l the bit length of the unknown.
        :return: the list of bounds
        """
        return [2 ** bit_length for value, bit_length in self._components if value is None]

    def to_int(self):
        """
        Converts this PartialInteger to an int.
        The number of unknowns must be zero.
        :return: the int represented by this PartialInteger
        """
        assert self.unknowns == 0
        return self.sub([])

    def to_string_le(self, base, symbols="0123456789abcdefghijklmnopqrstuvwxyz"):
        """
        Converts this PartialInteger to a list of characters in the provided base (little endian).
        :param base: the base, must be a power of two and less than or equal to 36
        :param symbols: the symbols to use, at least as many as base (default: "0123456789abcdefghijklmnopqrstuvwxyz")
        :return: the list of characters, with '?' representing an unknown digit
        """
        assert (base & (base - 1)) == 0, "Base must be power of two."
        assert base <= 36
        assert len(symbols) >= base
        bits_per_element = int(log2(base))
        chars = []
        for value, bit_length in self._components:
            assert bit_length % bits_per_element == 0, f"Component with bit length {bit_length} can't be represented by base {base} digits"
            for _ in range(bit_length // bits_per_element):
                if value is None:
                    chars.append('?')
                else:
                    chars.append(symbols[value % base])
                    value //= base

        return chars

    def to_string_be(self, base, symbols="0123456789abcdefghijklmnopqrstuvwxyz"):
        """
        Converts this PartialInteger to a list of characters in the provided base (big endian).
        :param base: the base, must be a power of two and less than or equal to 36
        :param symbols: the symbols to use, at least as many as base (default: "0123456789abcdefghijklmnopqrstuvwxyz")
        :return: the list of characters, with '?' representing an unknown digit
        """
        return self.to_string_le(base, symbols)[::-1]

    def to_bits_le(self, symbols="01"):
        """
        Converts this PartialInteger to a list of bit characters (little endian).
        :param symbols: the two symbols to use (default: "01")
        :return: the list of bit characters, with '?' representing an unknown bit
        """
        assert len(symbols) == 2
        return self.to_string_le(2, symbols)

    def to_bits_be(self, symbols="01"):
        """
        Converts this PartialInteger to a list of bit characters (big endian).
        :param symbols: the two symbols to use (default: "01")
        :return: the list of bit characters, with '?' representing an unknown bit
        """
        return self.to_bits_le(symbols)[::-1]

    def to_hex_le(self, symbols="0123456789abcdef"):
        """
        Converts this PartialInteger to a list of hex characters (little endian).
        :param symbols: the 16 symbols to use (default: "0123456789abcdef")
        :return: the list of hex characters, with '?' representing an unknown nibble
        """
        assert len(symbols) == 16
        return self.to_string_le(16, symbols)

    def to_hex_be(self, symbols="0123456789abcdef"):
        """
        Converts this PartialInteger to a list of hex characters (big endian).
        :param symbols: the 16 symbols to use (default: "0123456789abcdef")
        :return: the list of hex characters, with '?' representing an unknown nibble
        """
        return self.to_hex_le(symbols)[::-1]

    @staticmethod
    def unknown(bit_length):
        return PartialInteger().add_unknown(bit_length)

    @staticmethod
    def parse_le(digits, base):
        """
        Constructs a PartialInteger from arbitrary digits in a provided base (little endian).
        :param digits: the digits (string with '?' representing unknown or list with '?'/None representing unknown)
        :param base: the base, must be a power of two and less than or equal to 36
        :return: a PartialInteger with known and unknown components as indicated by the digits
        """
        assert (base & (base - 1)) == 0, "Base must be power of two."
        assert base <= 36
        bits_per_element = int(log2(base))
        p = PartialInteger()
        rc_k = 0
        rc_u = 0
        value = 0
        for digit in digits:
            if digit is None or digit == '?':
                if rc_k > 0:
                    p.add_known(value, rc_k * bits_per_element)
                    rc_k = 0
                    value = 0
                rc_u += 1
            else:
                if isinstance(digit, str):
                    digit = int(digit, base)
                assert 0 <= digit < base
                if rc_u > 0:
                    p.add_unknown(rc_u * bits_per_element)
                    rc_u = 0
                value += digit * base ** rc_k
                rc_k += 1

        if rc_k > 0:
            p.add_known(value, rc_k * bits_per_element)

        if rc_u > 0:
            p.add_unknown(rc_u * bits_per_element)

        return p

    @staticmethod
    def parse_be(digits, base):
        """
        Constructs a PartialInteger from arbitrary digits in a provided base (big endian).
        :param digits: the digits (string with '?' representing unknown or list with '?'/None representing unknown)
        :param base: the base (must be a power of two and less than or equal to 36)
        :return: a PartialInteger with known and unknown components as indicated by the digits
        """
        return PartialInteger.parse_le(reversed(digits), base)

    @staticmethod
    def from_bits_le(bits):
        """
        Constructs a PartialInteger from bits (little endian).
        :param bits: the bits (string with '?' representing unknown or list with '?'/None representing unknown)
        :return: a PartialInteger with known and unknown components as indicated by the bits
        """
        return PartialInteger.parse_le(bits, 2)

    @staticmethod
    def from_bits_be(bits):
        """
        Constructs a PartialInteger from bits (big endian).
        :param bits: the bits (string with '?' representing unknown or list with '?'/None representing unknown)
        :return: a PartialInteger with known and unknown components as indicated by the bits
        """
        return PartialInteger.from_bits_le(reversed(bits))

    @staticmethod
    def from_hex_le(hex):
        """
        Constructs a PartialInteger from hex characters (little endian).
        :param hex: the hex characters (string with '?' representing unknown or list with '?'/None representing unknown)
        :return: a PartialInteger with known and unknown components as indicated by the hex characters
        """
        return PartialInteger.parse_le(hex, 16)

    @staticmethod
    def from_hex_be(hex):
        """
        Constructs a PartialInteger from hex characters (big endian).
        :param hex: the hex characters (string with '?' representing unknown or list with '?'/None representing unknown)
        :return: a PartialInteger with known and unknown components as indicated by the hex characters
        """
        return PartialInteger.from_hex_le(reversed(hex))

    @staticmethod
    def from_lsb(bit_length, lsb, lsb_bit_length):
        """
        Constructs a PartialInteger from some known lsb, setting the msb to unknown.
        :param bit_length: the total bit length of the integer
        :param lsb: the known lsb
        :param lsb_bit_length: the bit length of the known lsb
        :return: a PartialInteger with one known component (the lsb) and one unknown component (the msb)
        """
        assert bit_length >= lsb_bit_length
        assert 0 <= lsb <= (2 ** lsb_bit_length)
        return PartialInteger().add_known(lsb, lsb_bit_length).add_unknown(bit_length - lsb_bit_length)

    @staticmethod
    def from_msb(bit_length, msb, msb_bit_length):
        """
        Constructs a PartialInteger from some known msb, setting the lsb to unknown.
        :param bit_length: the total bit length of the integer
        :param msb: the known msb
        :param msb_bit_length: the bit length of the known msb
        :return: a PartialInteger with one known component (the msb) and one unknown component (the lsb)
        """
        assert bit_length >= msb_bit_length
        assert 0 <= msb < (2 ** msb_bit_length)
        return PartialInteger().add_unknown(bit_length - msb_bit_length).add_known(msb, msb_bit_length)

    @staticmethod
    def from_lsb_and_msb(bit_length, lsb, lsb_bit_length, msb, msb_bit_length):
        """
        Constructs a PartialInteger from some known lsb and msb, setting the middle bits to unknown.
        :param bit_length: the total bit length of the integer
        :param lsb: the known lsb
        :param lsb_bit_length: the bit length of the known lsb
        :param msb: the known msb
        :param msb_bit_length: the bit length of the known msb
        :return: a PartialInteger with two known components (the lsb and msb) and one unknown component (the middle bits)
        """
        assert bit_length >= lsb_bit_length + msb_bit_length
        assert 0 <= lsb < (2 ** lsb_bit_length)
        assert 0 <= msb < (2 ** msb_bit_length)
        middle_bit_length = bit_length - lsb_bit_length - msb_bit_length
        return PartialInteger().add_known(lsb, lsb_bit_length).add_unknown(middle_bit_length).add_known(msb, msb_bit_length)

    @staticmethod
    def from_middle(middle, middle_bit_length, lsb_bit_length, msb_bit_length):
        """
        Constructs a PartialInteger from some known middle bits, setting the lsb and msb to unknown.
        :param middle: the known middle bits
        :param middle_bit_length: the bit length of the known middle bits
        :param lsb_bit_length: the bit length of the unknown lsb
        :param msb_bit_length: the bit length of the unknown msb
        :return: a PartialInteger with one known component (the middle bits) and two unknown components (the lsb and msb)
        """
        assert 0 <= middle < (2 ** middle_bit_length)
        return PartialInteger().add_unknown(lsb_bit_length).add_known(middle, middle_bit_length).add_unknown(msb_bit_length)

    @staticmethod
    def lsb_of(i, bit_length, lsb_bit_length):
        """
        Constructs a PartialInteger from the lsb of a known integer, setting the msb to unknown.
        Mainly used for testing purposes.
        :param i: the known integer
        :param bit_length: the total length of the known integer
        :param lsb_bit_length: the bit length of the known lsb
        :return: a PartialInteger with one known component (the lsb) and one unknown component (the msb)
        """
        lsb = i % (2 ** lsb_bit_length)
        return PartialInteger.from_lsb(bit_length, lsb, lsb_bit_length)

    @staticmethod
    def msb_of(i, bit_length, msb_bit_length):
        """
        Constructs a PartialInteger from the msb of a known integer, setting the lsb to unknown.
        Mainly used for testing purposes.
        :param i: the known integer
        :param bit_length: the total length of the known integer
        :param msb_bit_length: the bit length of the known msb
        :return: a PartialInteger with one known component (the msb) and one unknown component (the lsb)
        """
        msb = i >> (bit_length - msb_bit_length)
        return PartialInteger.from_msb(bit_length, msb, msb_bit_length)

    @staticmethod
    def lsb_and_msb_of(i, bit_length, lsb_bit_length, msb_bit_length):
        """
        Constructs a PartialInteger from the lsb and msb of a known integer, setting the middle bits to unknown.
        Mainly used for testing purposes.
        :param i: the known integer
        :param bit_length: the total length of the known integer
        :param lsb_bit_length: the bit length of the known lsb
        :param msb_bit_length: the bit length of the known msb
        :return: a PartialInteger with two known components (the lsb and msb) and one unknown component (the middle bits)
        """
        lsb = i % (2 ** lsb_bit_length)
        msb = i >> (bit_length - msb_bit_length)
        return PartialInteger.from_lsb_and_msb(bit_length, lsb, lsb_bit_length, msb, msb_bit_length)

    @staticmethod
    def middle_of(i, bit_length, lsb_bit_length, msb_bit_length):
        """
        Constructs a PartialInteger from the middle bits of a known integer, setting the lsb and msb to unknown.
        Mainly used for testing purposes.
        :param i: the known integer
        :param bit_length: the total length of the known integer
        :param lsb_bit_length: the bit length of the unknown lsb
        :param msb_bit_length: the bit length of the unknown msb
        :return: a PartialInteger with one known component (the middle bits) and two unknown components (the lsb and msb)
        """
        middle_bit_length = bit_length - lsb_bit_length - msb_bit_length
        middle = (i >> lsb_bit_length) % (2 ** middle_bit_length)
        return PartialInteger.from_middle(middle, middle_bit_length, lsb_bit_length, msb_bit_length)
