#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 16
KEY_SIZE = 32
MAC_KEY_SIZE = 32
TAG_SIZE = 32
ITERATIONS = 100000


def usage() -> None:
    print("Usage: pbenc_aes_ctr_hmac.py enc <fich> | dec <fich>", file=sys.stderr)


def derive_keys(passphrase: bytes, salt: bytes) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + MAC_KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    key_material = kdf.derive(passphrase)
    return key_material[:KEY_SIZE], key_material[KEY_SIZE:]


def read_passphrase() -> bytes:
    data = sys.stdin.buffer.read()
    return data.rstrip(b"\n")


def encrypt_file(fich: str) -> None:
    passphrase = read_passphrase()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key_enc, key_mac = derive_keys(passphrase, salt)

    with open(fich, "rb") as f:
        ptxt = f.read()

    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ctxt = encryptor.update(ptxt) + encryptor.finalize()

    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(nonce + ctxt)
    tag = h.finalize()

    with open(fich + ".enc", "wb") as f:
        f.write(salt + nonce + ctxt + tag)


def decrypt_file(fich: str) -> None:
    passphrase = read_passphrase()

    with open(fich, "rb") as f:
        data = f.read()

    if len(data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    tag = data[-TAG_SIZE:]
    ctxt = data[SALT_SIZE + NONCE_SIZE : -TAG_SIZE]

    key_enc, key_mac = derive_keys(passphrase, salt)

    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(nonce + ctxt)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    ptxt = decryptor.update(ctxt) + decryptor.finalize()

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
