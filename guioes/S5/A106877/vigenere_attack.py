#!/usr/bin/env python3

import itertools
import sys

from classical import caesar, preproc, shift_to_key, vigenere


PORTUGUESE_FREQ = {
    "A": 14.63,
    "E": 12.57,
    "O": 10.73,
    "S": 7.81,
    "R": 6.53,
    "I": 6.18,
    "N": 5.05,
    "D": 4.99,
    "M": 4.74,
    "U": 4.63,
    "T": 4.34,
    "C": 3.88,
    "L": 2.78,
    "P": 2.52,
    "V": 1.67,
    "G": 1.30,
    "H": 1.28,
    "B": 1.04,
    "F": 1.02,
    "Q": 1.20,
    "Z": 0.47,
    "J": 0.40,
    "X": 0.21,
    "K": 0.02,
    "W": 0.01,
    "Y": 0.01,
}


def usage():
    print(
        f"Usage: {sys.argv[0]} <key-size> <cryptogram> <word> [word ...]",
        file=sys.stderr,
    )
    sys.exit(1)


def chi_square(text):
    if not text:
        return float("inf")

    total = len(text)
    score = 0.0
    for letter, expected_percent in PORTUGUESE_FREQ.items():
        observed = text.count(letter)
        expected = total * expected_percent / 100.0
        score += ((observed - expected) ** 2) / expected
    return score


def ranked_shifts(slice_text):
    candidates = []
    for shift in range(26):
        candidate_plaintext = caesar(slice_text, -shift)
        candidates.append((chi_square(candidate_plaintext), shift))
    candidates.sort()
    return [shift for _, shift in candidates]


def main():
    if len(sys.argv) < 4:
        usage()

    try:
        key_size = int(sys.argv[1])
    except ValueError:
        usage()
    if key_size <= 0:
        usage()

    cryptogram = preproc(sys.argv[2])
    words = [preproc(word) for word in sys.argv[3:]]
    slices = [cryptogram[index::key_size] for index in range(key_size)]
    candidates_by_position = [ranked_shifts(slice_text) for slice_text in slices]

    # Try the most likely Caesar shifts first, gradually widening the search.
    for width in range(1, 27):
        search_space = [candidates[:width] for candidates in candidates_by_position]
        for shifts in itertools.product(*search_space):
            key = "".join(shift_to_key(shift) for shift in shifts)
            plaintext = vigenere(cryptogram, key, decrypt=True)
            if any(word and word in plaintext for word in words):
                print(key)
                print(plaintext)
                return


if __name__ == "__main__":
    main()
