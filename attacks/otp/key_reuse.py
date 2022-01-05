from math import log10


def _hamming_distance(a, b):
    distance = 0
    for x, y in zip(a, b):
        distance += (x ^ y).bit_count()

    return distance


def _guess_key_sizes(c: list[bytes], max_key_size):
    key_sizes = []
    prev_distance = None
    for key_size in range(2, max_key_size + 1):
        blocks = []
        for ci in c:
            j = 0
            while (j + 1) * key_size <= len(ci):
                blocks.append(ci[j * key_size:(j + 1) * key_size])
                j += 1

        if len(blocks) < 2:
            continue

        distance = 0
        for i in range(len(blocks) - 1):
            distance += _hamming_distance(blocks[i], blocks[i + 1])

        distance /= len(blocks) - 1
        distance /= key_size
        if prev_distance is not None:
            diff = prev_distance - distance

            key_sizes.append((key_size, diff))

        prev_distance = distance

    return [x[0] for x in sorted(key_sizes, key=lambda x: x[1], reverse=True)]


def _score(p, char_frequencies, char_floor):
    score = 0
    for b in p:
        c = chr(b)
        if not c.isascii():
            return None

        if not (c.isprintable() or c.isspace()):
            return None

        c = c.lower()
        if c in char_frequencies:
            score += log10(char_frequencies[c])
        else:
            score += char_floor

    return score


def _transpose(c, i, key_size):
    transposed = bytearray()
    for c in c:
        j = 0
        while j + i < len(c):
            transposed.append(c[j + i])
            j += key_size

    return transposed


def _frequency_analysis(c, char_frequencies, char_floor):
    max_score = float("-inf")
    candidate_k = None
    for k in range(256):
        p = bytes([b ^ k for b in c])
        score = _score(p, char_frequencies, char_floor)
        if score is not None and score > max_score:
            max_score = score
            candidate_k = k

    return candidate_k


def attack(c, char_frequencies, char_floor, key_size=None):
    """
    Breaks the one-time pad when the key is reused in a single plaintext or multiple plaintexts.
    Note: this implementation is very primitive and only for educational purposes. For more real-world analysis, use xortool.
    :param c: the list of ciphertexts
    :param char_frequencies: a dict of (char, frequency) items for the plaintext language
    :param char_floor: the value to assign to a character if it is not found in char_frequencies
    :param key_size: the size of the key in bytes (default: None): if no key size is given, this method attempts to discover it using the Hamming distance
    :return: the best guess for the key
    """
    if key_size is None:
        key_sizes = _guess_key_sizes(c, max(map(lambda ci: len(ci), c)))
    else:
        key_sizes = [key_size]

    for key_size in key_sizes:
        k = bytearray(key_size)
        for i in range(key_size):
            transposed = _transpose(c, i, key_size)
            candidate_k = _frequency_analysis(transposed, char_frequencies, char_floor)
            if candidate_k is None:
                break
            else:
                k[i] = candidate_k
        else:
            return k
