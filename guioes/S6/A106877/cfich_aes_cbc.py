#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_SIZE = 32
IV_SIZE = 16


def usage() -> None:
    print(
        "Usage: cfich_aes_cbc.py setup <fkey> | enc <fich> <fkey> | dec <fich> <fkey>",
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


def encrypt_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    iv = os.urandom(IV_SIZE)

    with open(fich, "rb") as f:
        ptxt = f.read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(ptxt) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ctxt = encryptor.update(padded) + encryptor.finalize()

    with open(fich + ".enc", "wb") as f:
        f.write(iv + ctxt)


def decrypt_file(fich: str, fkey: str) -> None:
    key = read_key(fkey)

    with open(fich, "rb") as f:
        data = f.read()

    if len(data) < IV_SIZE:
        raise ValueError("Ciphertext too short")

    iv = data[:IV_SIZE]
    ctxt = data[IV_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ctxt) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    ptxt = unpadder.update(padded) + unpadder.finalize()

    with open(fich + ".dec", "wb") as f:
        f.write(ptxt)


def main() -> int:
    if len(sys.argv) < 3:
        usage()
        return 1

    op = sys.argv[1]
    try:
        if op == "setup" and len(sys.argv) == 3:
            write_key(sys.argv[2])
        elif op == "enc" and len(sys.argv) == 4:
            encrypt_file(sys.argv[2], sys.argv[3])
        elif op == "dec" and len(sys.argv) == 4:
            decrypt_file(sys.argv[2], sys.argv[3])
        else:
            usage()
            return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
