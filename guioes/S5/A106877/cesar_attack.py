#!/usr/bin/env python3

import sys

from classical import caesar, preproc, shift_to_key


def usage():
    print(f"Usage: {sys.argv[0]} <cryptogram> <word> [word ...]", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) < 3:
        usage()

    cryptogram = sys.argv[1]
    words = [preproc(word) for word in sys.argv[2:]]

    for shift in range(26):
        plaintext = caesar(cryptogram, -shift)
        if any(word and word in plaintext for word in words):
            print(shift_to_key(shift))
            print(plaintext)
            return


if __name__ == "__main__":
    main()
