"""
client/keystore.py

Identidade: par X25519 por utilizador.
  - Privada cifrada com AES-256-GCM (chave derivada da password via PBKDF2)
  - Pública registada no servidor

Chaves de contactos: chave AES-256 por par (owner, contact)
  - Cifrada com AES-256-GCM usando chave derivada da privada do owner via HKDF
  - Só o owner (com a sua priv) consegue recuperar

Ficheiro de identidade: <keys_dir>/<username>.json
Ficheiro de contactos:  <keys_dir>/<username>_contacts.json
"""

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes


class KeyStore:
    def __init__(self, keys_dir: str):
        self.keys_dir = os.path.abspath(keys_dir)

    def _key_path(self, username: str) -> str:
        return os.path.join(self.keys_dir, f"{username.replace(os.sep, '_')}.json")

    def _contacts_path(self, username: str) -> str:
        return os.path.join(self.keys_dir, f"{username.replace(os.sep, '_')}_contacts.json")

    @staticmethod
    def _derive_key_from_password(password: str, salt: bytes) -> bytes:
        # PBKDF2: torna a password num segredo de 32 bytes resistente a brute-force
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150_000)
        return kdf.derive(password.encode())

    @staticmethod
    def _derive_key_from_priv(priv: X25519PrivateKey) -> bytes:
        # HKDF sobre os bytes raw da privada - chave AES-256 dedicada ao armazenamento de contactos
        # info diferente do handshake garante que esta chave nunca é usada para outro fim
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"contact-key-storage").derive(priv_bytes)

    # ------------------------------------------------------------------ #
    # Identidade                                                          #
    # ------------------------------------------------------------------ #

    def has_local_keys(self, username: str) -> bool:
        return os.path.exists(self._key_path(username))

    def delete_local_keys(self, username: str):
        for path in [self._key_path(username), self._contacts_path(username)]:
            if os.path.exists(path):
                os.remove(path)

    def generate_and_save(self, username: str, password: str) -> tuple[str, str]:
        """
        Gera par X25519, cifra a privada com a password e guarda em disco.
        Devolve (pub_b64, blob_b64) para enviar ao servidor.
        blob = base64(salt[16] + nonce[12] + enc_priv)
        """
        os.makedirs(self.keys_dir, exist_ok=True)

        priv      = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        salt     = os.urandom(16)
        nonce    = os.urandom(12)
        enc_priv = AESGCM(self._derive_key_from_password(password, salt)).encrypt(nonce, priv_bytes, None)

        with open(self._key_path(username), "w") as f:
            json.dump({
                "pub":      base64.b64encode(pub_bytes).decode(),
                "salt":     base64.b64encode(salt).decode(),
                "nonce":    base64.b64encode(nonce).decode(),
                "enc_priv": base64.b64encode(enc_priv).decode(),
            }, f, indent=2)

        pub_b64  = base64.b64encode(pub_bytes).decode()
        blob_b64 = base64.b64encode(salt + nonce + enc_priv).decode()
        return pub_b64, blob_b64

    def save_from_server(self, username: str, pub_b64: str, blob_b64: str):
        """Guarda chaves recebidas do servidor (novo dispositivo)."""
        os.makedirs(self.keys_dir, exist_ok=True)
        raw  = base64.b64decode(blob_b64)
        salt, nonce, enc_priv = raw[:16], raw[16:28], raw[28:]
        with open(self._key_path(username), "w") as f:
            json.dump({
                "pub":      pub_b64,
                "salt":     base64.b64encode(salt).decode(),
                "nonce":    base64.b64encode(nonce).decode(),
                "enc_priv": base64.b64encode(enc_priv).decode(),
            }, f, indent=2)

    def load_private_key(self, username: str, password: str) -> X25519PrivateKey:
        """Decifra e devolve a chave privada X25519. Lança ValueError se a password for errada."""
        path = self._key_path(username)
        if not os.path.exists(path):
            raise ValueError(f"Sem chaves locais para '{username}'.")

        with open(path) as f:
            d = json.load(f)

        salt     = base64.b64decode(d["salt"])
        nonce    = base64.b64decode(d["nonce"])
        enc_priv = base64.b64decode(d["enc_priv"])

        try:
            priv_bytes = AESGCM(self._derive_key_from_password(password, salt)).decrypt(nonce, enc_priv, None)
        except Exception:
            raise ValueError("Password incorrecta ou ficheiro de chaves corrompido.")

        return X25519PrivateKey.from_private_bytes(priv_bytes)

    def load_public_key_bytes(self, username: str) -> bytes:
        with open(self._key_path(username)) as f:
            return base64.b64decode(json.load(f)["pub"])

    # ------------------------------------------------------------------ #
    # Chaves de contactos                                                 #
    # ------------------------------------------------------------------ #

    def save_contact_key(self, owner: str, contact: str,
                         sym_key: bytes, owner_priv: X25519PrivateKey):
        """
        Cifra sym_key com AES-GCM usando chave derivada da priv do owner e guarda em disco.
        Formato: { contact: { nonce: b64, enc_key: b64 } }
        """
        aes_key = self._derive_key_from_priv(owner_priv)
        nonce   = os.urandom(12)
        enc_key = AESGCM(aes_key).encrypt(nonce, sym_key, None)

        path = self._contacts_path(owner)
        data = {}
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)

        data[contact] = {
            "nonce":   base64.b64encode(nonce).decode(),
            "enc_key": base64.b64encode(enc_key).decode(),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def get_contact_key(self, owner: str, contact: str,
                        owner_priv: X25519PrivateKey) -> bytes | None:
        """Decifra e devolve a chave simétrica do contacto usando a priv do owner."""
        path = self._contacts_path(owner)
        if not os.path.exists(path):
            return None

        with open(path) as f:
            data = json.load(f)

        entry = data.get(contact)
        if not entry:
            return None

        aes_key = self._derive_key_from_priv(owner_priv)
        nonce   = base64.b64decode(entry["nonce"])
        enc_key = base64.b64decode(entry["enc_key"])

        try:
            return AESGCM(aes_key).decrypt(nonce, enc_key, None)
        except Exception:
            return None

    def generate_contact_key(self, owner: str, contact: str,
                              contact_pub_b64: str,
                              owner_priv: X25519PrivateKey) -> str:
        """
        Gera chave AES-256 para comunicação com `contact`.
        1. Guarda-a cifrada com chave derivada da priv do owner (para o owner recuperar depois)
        2. Cifra-a com a pub_key do contact via ECDH para enviar ao servidor
           O contact decifra com a sua priv quando receber.

        Devolve (sym_key_plaintext, enc_for_contact_b64).
        enc_for_contact = base64(eph_pub[32] + nonce[12] + enc_key)
        """
        sym_key = os.urandom(32)

        # Guardar para o owner
        self.save_contact_key(owner, contact, sym_key, owner_priv)

        # Cifrar para o contact: ECDH entre chave efemera e pub do contact
        print("boas")
        contact_pub = X25519PublicKey.from_public_bytes(base64.b64decode(contact_pub_b64))
        print("boas2")
        eph_priv    = X25519PrivateKey.generate()
        eph_pub     = eph_priv.public_key()
        shared  = eph_priv.exchange(contact_pub)

        # Como o protocolo não permite cifrar com a chave publica do contacto diretamente
        # temos de derivar uma chave AES com um shared por DH para cifrar
        # o contacto pode entao recalcular shared e derivar a chave AES
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"contact-key-exchange").derive(shared)
        nonce   = os.urandom(12)
        enc_key = AESGCM(aes_key).encrypt(nonce, sym_key, None)

        eph_pub_bytes   = eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        enc_for_contact = base64.b64encode(eph_pub_bytes + nonce + enc_key).decode()

        return enc_for_contact