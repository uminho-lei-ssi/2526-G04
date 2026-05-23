#!/usr/bin/env python3
import sys

NONCE_SIZE = 16


def usage() -> None:
    print(
        "Usage: chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>",
        file=sys.stderr,
    )


def main() -> int:
    if len(sys.argv) != 5:
        usage()
        return 1

    fctxt = sys.argv[1]
    try:
        pos = int(sys.argv[2])
    except ValueError:
        print("Error: pos must be an integer", file=sys.stderr)
        return 1

    ptxt_at_pos = sys.argv[3].encode()
    new_ptxt_at_pos = sys.argv[4].encode()

    if len(ptxt_at_pos) != len(new_ptxt_at_pos):
        print("Error: ptxtAtPos and newPtxtAtPos must have same length", file=sys.stderr)
        return 1

    with open(fctxt, "rb") as f:
        data = f.read()

    if len(data) < NONCE_SIZE:
        print("Error: ciphertext too short", file=sys.stderr)
        return 1

    nonce = data[:NONCE_SIZE]
    ctxt = bytearray(data[NONCE_SIZE:])

    if pos < 0 or pos + len(ptxt_at_pos) > len(ctxt):
        print("Error: position out of range", file=sys.stderr)
        return 1

    for i in range(len(ptxt_at_pos)):
        ctxt[pos + i] ^= ptxt_at_pos[i] ^ new_ptxt_at_pos[i]

    with open(fctxt + ".attck", "wb") as f:
        f.write(nonce + ctxt)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
