#!/usr/bin/env python3

import sys

from classical import vigenere


def usage():
    print(f"Usage: {sys.argv[0]} <enc|dec> <key> <message>", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in {"enc", "dec"}:
        usage()

    print(vigenere(sys.argv[3], sys.argv[2], decrypt=(sys.argv[1] == "dec")))


if __name__ == "__main__":
    main()
