#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 100000


def usage() -> None:
    print("Usage: pbenc_aes_gcm.py enc <fich> | dec <fich>", file=sys.stderr)


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase)


def read_passphrase() -> bytes:
    data = sys.stdin.buffer.read()
    return data.rstrip(b"\n")


def encrypt_file(fich: str) -> None:
    passphrase = read_passphrase()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)

    with open(fich, "rb") as f:
        ptxt = f.read()

    aesgcm = AESGCM(key)
    ctxt = aesgcm.encrypt(nonce, ptxt, None)

    with open(fich + ".enc", "wb") as f:
        f.write(salt + nonce + ctxt)


def decrypt_file(fich: str) -> None:
    passphrase = read_passphrase()

    with open(fich, "rb") as f:
        data = f.read()

    if len(data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Ciphertext too short")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ctxt = data[SALT_SIZE + NONCE_SIZE :]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ptxt = aesgcm.decrypt(nonce, ctxt, None)

    with open(fich + ".dec", "wb") as f:
        f.write(ptxt)


def main() -> int:
    if len(sys.argv) < 3:
        usage()
        return 1

    op = sys.argv[1]
    try:
        if op == "enc" and len(sys.argv) == 3:
            encrypt_file(sys.argv[2])
        elif op == "dec" and len(sys.argv) == 3:
            decrypt_file(sys.argv[2])
        else:
            usage()
            return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
