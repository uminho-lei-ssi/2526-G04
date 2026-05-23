#!/usr/bin/env python3

import random
import sys

from classical import xor_bytes


def usage():
    print(
        f"Usage: {sys.argv[0]} <key-size> <cipher-file> <word> [word ...]",
        file=sys.stderr,
    )
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as file:
        return file.read()


def key_from_seed(seed, nbytes):
    random.seed(seed)
    return random.randbytes(nbytes)


def main():
    if len(sys.argv) < 4:
        usage()

    try:
        key_size = int(sys.argv[1])
    except ValueError:
        usage()
    if key_size <= 0:
        usage()

    cryptogram = read_file(sys.argv[2])
    words = [word.encode("utf-8") for word in sys.argv[3:]]

    for seed_value in range(2**16):
        seed = seed_value.to_bytes(2, "big")
        key = key_from_seed(seed, key_size)
        if len(key) < len(cryptogram):
            continue
        plaintext = xor_bytes(cryptogram, key)
        if any(word and word in plaintext for word in words):
            sys.stdout.buffer.write(plaintext)
            return


if __name__ == "__main__":
    main()
