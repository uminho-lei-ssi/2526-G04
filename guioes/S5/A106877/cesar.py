#!/usr/bin/env python3

import sys

from classical import caesar, key_to_shift


def usage():
    print(f"Usage: {sys.argv[0]} <enc|dec> <A-Z> <message>", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in {"enc", "dec"}:
        usage()

    shift = key_to_shift(sys.argv[2])
    if sys.argv[1] == "dec":
        shift = -shift

    print(caesar(sys.argv[3], shift))


if __name__ == "__main__":
    main()
