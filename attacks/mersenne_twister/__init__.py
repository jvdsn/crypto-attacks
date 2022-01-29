class MersenneTwister:
    def __init__(self, w, n, m, r, a, b, c, s, t, u, d, l):
        self.w = w
        self.n = n
        self.m = m
        self.a = a
        self.b = b
        self.c = c
        self.s = s
        self.t = t
        self.u = u
        self.d = d
        self.l = l
        self.mt = [0] * n
        self.index = n + 1
        self.lower_mask = (1 << r) - 1
        self.upper_mask = (~self.lower_mask) % (2 ** self.w)

    def seed(self, f, seed):
        self.index = self.n
        self.mt[0] = seed
        for i in range(1, self.n):
            self.mt[i] = (f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i) % (2 ** self.w)

    def _twist(self):
        for i in range(self.n):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0

    def __next__(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise ValueError("Generator was never seeded")
            self._twist()

        y = self.mt[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l
        self.index += 1
        return y % (2 ** self.w)


def mt19937():
    """
    Constructs a new unseeded MT19937 instance.
    :return: the new MT19937 instance
    """
    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    b = 0x9D2C5680
    c = 0xEFC60000
    s = 7
    t = 15
    u = 11
    d = 0xFFFFFFFF
    l = 18
    return MersenneTwister(w, n, m, r, a, b, c, s, t, u, d, l)


def mt19937_64():
    """
    Constructs a new unseeded MT19937-64 instance.
    :return: the new MT19937-64 instance
    """
    w = 64
    n = 312
    m = 156
    r = 31
    a = 0xB5026F5AA96619E9
    b = 0x71D67FFFEDA60000
    c = 0xFFF7EEE000000000
    s = 17
    t = 37
    u = 29
    d = 0x5555555555555555
    l = 43
    return MersenneTwister(w, n, m, r, a, b, c, s, t, u, d, l)
