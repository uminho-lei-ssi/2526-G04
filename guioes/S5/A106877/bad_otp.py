#!/usr/bin/env python3

import random
import sys

from classical import xor_bytes


def bad_prng(n):
    """An insecure pseudo-random number generator."""
    random.seed(random.randbytes(2))
    return random.randbytes(n)


def usage():
    print(
        f"Usage: {sys.argv[0]} setup <nbytes> <keyfile>\n"
        f"       {sys.argv[0]} enc <message-file> <keyfile>\n"
        f"       {sys.argv[0]} dec <cipher-file> <keyfile>",
        file=sys.stderr,
    )
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as file:
        return file.read()


def write_file(path, data):
    with open(path, "wb") as file:
        file.write(data)


def setup(nbytes, keyfile):
    write_file(keyfile, bad_prng(nbytes))


def enc_or_dec(input_file, keyfile, suffix):
    data = read_file(input_file)
    key = read_file(keyfile)
    output = xor_bytes(data, key)
    write_file(input_file + suffix, output)
    sys.stdout.buffer.write(output)


def main():
    if len(sys.argv) != 4:
        usage()

    operation = sys.argv[1]
    if operation == "setup":
        try:
            nbytes = int(sys.argv[2])
        except ValueError:
            usage()
        if nbytes < 0:
            usage()
        setup(nbytes, sys.argv[3])
    elif operation == "enc":
        enc_or_dec(sys.argv[2], sys.argv[3], ".enc")
    elif operation == "dec":
        enc_or_dec(sys.argv[2], sys.argv[3], ".dec")
    else:
        usage()


if __name__ == "__main__":
    main()
