#!/usr/bin/env python3
import hmac
import os
import sys
from cryptography.hazmat.primitives import hashes

KEY_SIZE = 32


def usage() -> None:
    print(
        "Usage: mac_sha256.py setup <fkey> | mac <fich> <fkey> | ver <fich> <fkey>",
        file=sys.stderr,
    )


def read_key(path: str) -> bytes:
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != KEY_SIZE:
        raise ValueError("Invalid key size")
    return key


def write_key(path: str) -> None:
    key = os.urandom(KEY_SIZE)
    with open(path, "wb") as f:
        f.write(key)


def compute_mac(key: bytes, data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    digest.update(data)
    return digest.finalize()


def mac_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    with open(fich, "rb") as f:
        data = f.read()
    tag = compute_mac(key, data)
    with open(fich + ".mac", "wb") as f:
        f.write(tag)


def ver_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    with open(fich, "rb") as f:
        data = f.read()
    with open(fich + ".mac", "rb") as f:
        tag = f.read()

    expected = compute_mac(key, data)
    print(hmac.compare_digest(expected, tag))


def main() -> int:
    if len(sys.argv) < 3:
        usage()
        return 1

    op = sys.argv[1]
    try:
        if op == "setup" and len(sys.argv) == 3:
            write_key(sys.argv[2])
        elif op == "mac" and len(sys.argv) == 4:
            mac_file(sys.argv[2], sys.argv[3])
        elif op == "ver" and len(sys.argv) == 4:
            ver_file(sys.argv[2], sys.argv[3])
        else:
            usage()
            return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
