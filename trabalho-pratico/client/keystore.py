"""
client/keystore.py — Estado local do cliente: par de chaves Ed25519.

A chave privada é cifrada com AES-256-GCM usando uma chave derivada da
password via PBKDF2. Nunca é guardada em plaintext.

Ficheiro em disco: <keys_dir>/<username>.json
{
    "pub":      "<base64>",   # chave pública raw (32 bytes)
    "salt":     "<base64>",   # salt PBKDF2
    "nonce":    "<base64>",   # nonce AES-GCM
    "enc_priv": "<base64>"    # chave privada cifrada
}
"""

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KeyStore:
    def __init__(self, keys_dir: str):
        self.keys_dir = os.path.abspath(keys_dir)

    def _key_path(self, username: str) -> str:
        safe_username = username.replace(os.sep, "_")
        return os.path.join(self.keys_dir, f"{safe_username}.json")

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=150_000,
        )
        return kdf.derive(password.encode())

    def has_local_keys(self, username: str) -> bool:
        return os.path.exists(self._key_path(username))

    def delete_local_keys(self, username: str):
        path = self._key_path(username)
        if os.path.exists(path):
            os.remove(path)

    def generate_and_save(self, username: str, password: str) -> tuple[str, str]:
        """
        Gera par Ed25519, cifra a privada com a password, guarda em disco.
        Devolve (pub_b64, enc_priv_b64) para enviar ao servidor.
        enc_priv_b64 = base64(salt + nonce + ciphertext) — tudo junto para o servidor guardar.
        """
        os.makedirs(self.keys_dir, exist_ok=True)

        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        salt = os.urandom(16)
        nonce = os.urandom(12)
        enc_priv = AESGCM(self._derive_key(password, salt)).encrypt(nonce, priv_bytes, None)

        pub_b64 = base64.b64encode(pub_bytes).decode()
        salt_b64 = base64.b64encode(salt).decode()
        nonce_b64 = base64.b64encode(nonce).decode()
        enc_priv_b64 = base64.b64encode(enc_priv).decode()

        with open(self._key_path(username), "w") as f:
            json.dump({"pub": pub_b64, "salt": salt_b64,
                       "nonce": nonce_b64, "enc_priv": enc_priv_b64}, f, indent=2)

        blob = base64.b64encode(salt + nonce + enc_priv).decode()
        return pub_b64, blob

    def save_from_server(self, username: str, pub_b64: str, blob_b64: str):
        """Guarda as chaves recebidas do servidor em disco local."""
        os.makedirs(self.keys_dir, exist_ok=True)
        raw = base64.b64decode(blob_b64)
        salt, nonce, enc_priv = raw[:16], raw[16:28], raw[28:]
        with open(self._key_path(username), "w") as f:
            json.dump({
                "pub": pub_b64,
                "salt": base64.b64encode(salt).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "enc_priv": base64.b64encode(enc_priv).decode(),
            }, f, indent=2)

    def load_private_key(self, username: str, password: str) -> Ed25519PrivateKey:
        """
        Carrega e decifra a chave privada do disco.
        Lança ValueError se a password for errada ou ficheiro não existir.
        """
        path = self._key_path(username)
        if not os.path.exists(path):
            raise ValueError(f"Sem chaves locais para '{username}'.")

        with open(path) as f:
            data = json.load(f)

        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        enc_priv = base64.b64decode(data["enc_priv"])

        try:
            priv_bytes = AESGCM(self._derive_key(password, salt)).decrypt(nonce, enc_priv, None)
        except Exception:
            raise ValueError("Password incorrecta ou ficheiro de chaves corrompido.")

        return Ed25519PrivateKey.from_private_bytes(priv_bytes)