"""
client/storage/keystore.py

Modelo Híbrido: Master Seed Aleatória
  - Master Seed (32 bytes) cifrada com AES-256-GCM (chave derivada da password via PBKDF2)
  - Identidade: par X25519 derivado da Master Seed via HKDF (info="identity-key")
  - Armazenamento de contactos: chave AES-256 derivada da Master Seed via HKDF (info="contact-key-storage")

Identificador público: SHA-256(username) em hex — username partilhado fora de banda para adicionar contactos.
  - Determinístico: qualquer dispositivo calcula o mesmo valor

Ficheiro de identidade:  <keys_dir>/<username>.json
Ficheiro de contactos:   <keys_dir>/<username>_contacts.json
  { "uid": { "nonce": b64, "enc_key": b64, "username": str | null } }
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
    def username_to_uid(username: str) -> str:
        """SHA-256(username) em hex — identificador público opaco."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(username.encode())
        return digest.finalize().hex()

    @staticmethod
    def _derive_key_from_password(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150_000)
        return kdf.derive(password.encode())

    @staticmethod
    def _derive_identity_from_seed(seed: bytes) -> X25519PrivateKey:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"identity-key")
        return X25519PrivateKey.from_private_bytes(hkdf.derive(seed))

    @staticmethod
    def _derive_storage_key_from_seed(seed: bytes) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"contact-key-storage")
        return hkdf.derive(seed)

    # ------------------------------------------------------------------ #
    # Identidade / Master Seed                                           #
    # ------------------------------------------------------------------ #

    def has_local_keys(self, username: str) -> bool:
        return os.path.exists(self._key_path(username))

    def delete_local_keys(self, username: str):
        for path in [self._key_path(username), self._contacts_path(username)]:
            if os.path.exists(path):
                os.remove(path)

    def generate_and_save(self, username: str, password: str) -> tuple[str, str]:
        """
        Gera Master Seed, deriva par X25519, cifra seed com password e guarda.
        Devolve (pub_b64, blob_b64) para enviar ao servidor no registo.
        blob = base64(salt[16] + nonce[12] + enc_seed)
        """
        os.makedirs(self.keys_dir, exist_ok=True)

        master_seed = os.urandom(32)
        priv        = self._derive_identity_from_seed(master_seed)
        pub_bytes   = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        salt     = os.urandom(16)
        nonce    = os.urandom(12)
        enc_seed = AESGCM(self._derive_key_from_password(password, salt)).encrypt(nonce, master_seed, None)

        with open(self._key_path(username), "w") as f:
            json.dump({
                "pub":      base64.b64encode(pub_bytes).decode(),
                "salt":     base64.b64encode(salt).decode(),
                "nonce":    base64.b64encode(nonce).decode(),
                "enc_seed": base64.b64encode(enc_seed).decode(),
            }, f, indent=2)

        return base64.b64encode(pub_bytes).decode(), base64.b64encode(salt + nonce + enc_seed).decode()

    def save_from_server(self, username: str, pub_b64: str, blob_b64: str):
        """Guarda chaves recebidas do servidor (novo dispositivo)."""
        os.makedirs(self.keys_dir, exist_ok=True)
        raw  = base64.b64decode(blob_b64)
        salt, nonce, enc_seed = raw[:16], raw[16:28], raw[28:]
        with open(self._key_path(username), "w") as f:
            json.dump({
                "pub":      pub_b64,
                "salt":     base64.b64encode(salt).decode(),
                "nonce":    base64.b64encode(nonce).decode(),
                "enc_seed": base64.b64encode(enc_seed).decode(),
            }, f, indent=2)

    def load_master_seed(self, username: str, password: str) -> bytes:
        """Decifra e devolve a Master Seed. Lança ValueError se a password for errada."""
        path = self._key_path(username)
        if not os.path.exists(path):
            raise ValueError(f"Sem chaves locais para '{username}'.")

        with open(path) as f:
            d = json.load(f)

        salt     = base64.b64decode(d["salt"])
        nonce    = base64.b64decode(d["nonce"])
        enc_seed = base64.b64decode(d["enc_seed"])

        try:
            return AESGCM(self._derive_key_from_password(password, salt)).decrypt(nonce, enc_seed, None)
        except Exception:
            raise ValueError("Password incorrecta ou ficheiro de chaves corrompido.")

    def load_public_key_bytes(self, username: str) -> bytes:
        with open(self._key_path(username)) as f:
            return base64.b64decode(json.load(f)["pub"])

    # ------------------------------------------------------------------ #
    # Resolução UID - username                                           #
    # ------------------------------------------------------------------ #

    def _load_contacts(self, owner: str) -> dict:
        path = self._contacts_path(owner)
        if not os.path.exists(path):
            return {}
        with open(path) as f:
            return json.load(f)

    def _save_contacts(self, owner: str, data: dict):
        os.makedirs(self.keys_dir, exist_ok=True)
        with open(self._contacts_path(owner), "w") as f:
            json.dump(data, f, indent=2)

    def save_contact_username(self, owner: str, contact: str, username: str):
        """Guarda o username real de um contacto após troca cifrada."""
        data = self._load_contacts(owner)
        if contact not in data:
            data[contact] = {}
        data[contact]["username"] = username
        self._save_contacts(owner, data)

    def resolve_uid(self, owner: str, uid: str) -> str | None:
        """Devolve o username local de um UID, ou None se ainda não resolvido."""
        return self._load_contacts(owner).get(uid, {}).get("username")

    def resolve_username_to_uid(self, owner: str, username: str) -> str | None:
        """Devolve o UID correspondente a um username local ou calcula diretamente."""
        # primeiro tenta pelo ficheiro de contactos para confirmar se ja existe
        data = self._load_contacts(owner)
        for uid, entry in data.items():
            if isinstance(entry, dict) and entry.get("username") == username:
                return uid
        # Fallback: calcular directamente
        return self.username_to_uid(username)

    # ------------------------------------------------------------------ #
    # Chaves de contactos                                                 #
    # ------------------------------------------------------------------ #

    def receive_contact_key(self, owner: str, sender_uid: str,
                            enc_blob_b64: str, master_seed: bytes):
        """Decifra chave simétrica enviada via ECDH e guarda localmente."""
        owner_priv = self._derive_identity_from_seed(master_seed)

        raw     = base64.b64decode(enc_blob_b64)
        eph_pub = X25519PublicKey.from_public_bytes(raw[:32])
        nonce   = raw[32:44]
        enc_key = raw[44:]

        shared  = owner_priv.exchange(eph_pub)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"contact-key-exchange").derive(shared)

        sym_key = AESGCM(aes_key).decrypt(nonce, enc_key, None)
        self.save_contact_key(owner, sender_uid, sym_key, master_seed)

    def receive_owner_key(self, owner: str, contact: str,
                          blob: str, master_seed: bytes):
        """Decifra chave simétrica cifrada com a storage key e guarda localmente."""
        aes_key_storage = self._derive_storage_key_from_seed(master_seed)
        raw = base64.b64decode(blob)
        nonce, enc_key = raw[:12], raw[12:]
        sym_key = AESGCM(aes_key_storage).decrypt(nonce, enc_key, None)
        self.save_contact_key(owner, contact, sym_key, master_seed)

    def save_contact_key(self, owner: str, contact: str,
                         sym_key: bytes, master_seed: bytes) -> str:
        """Cifra sym_key com a storage key e guarda. Devolve base64(nonce+enc_key)."""
        aes_key_storage = self._derive_storage_key_from_seed(master_seed)
        nonce   = os.urandom(12)
        enc_key = AESGCM(aes_key_storage).encrypt(nonce, sym_key, None)

        data = self._load_contacts(owner)
        if contact not in data:
            data[contact] = {}
        data[contact]["nonce"]   = base64.b64encode(nonce).decode()
        data[contact]["enc_key"] = base64.b64encode(enc_key).decode()
        self._save_contacts(owner, data)

        return base64.b64encode(nonce + enc_key).decode()

    def get_contact_key(self, owner: str, contact: str,
                        master_seed: bytes) -> bytes | None:
        """Decifra e devolve a chave simétrica do contacto."""
        entry = self._load_contacts(owner).get(contact)
        if not entry or "nonce" not in entry:
            return None

        aes_key_storage = self._derive_storage_key_from_seed(master_seed)
        try:
            return AESGCM(aes_key_storage).decrypt(
                base64.b64decode(entry["nonce"]),
                base64.b64decode(entry["enc_key"]),
                None
            )
        except Exception:
            return None

    def generate_contact_key(self, owner: str, contact: str,
                              contact_pub_b64: str,
                              master_seed: bytes) -> tuple[str, str]:
        """
        Gera chave AES-256 para comunicação com contact.
        Devolve (enc_for_contact, enc_for_self).
        enc_for_contact = base64(eph_pub[32] + nonce[12] + enc_key)   — ECDH
        enc_for_self    = base64(nonce[12] + enc_key)                 — storage key
        """
        sym_key      = os.urandom(32)
        enc_for_self = self.save_contact_key(owner, contact, sym_key, master_seed)

        contact_pub = X25519PublicKey.from_public_bytes(base64.b64decode(contact_pub_b64))
        eph_priv    = X25519PrivateKey.generate()
        shared      = eph_priv.exchange(contact_pub)

        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"contact-key-exchange").derive(shared)
        nonce   = os.urandom(12)
        enc_key = AESGCM(aes_key).encrypt(nonce, sym_key, None)

        eph_pub_bytes   = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        enc_for_contact = base64.b64encode(eph_pub_bytes + nonce + enc_key).decode()

        return enc_for_contact, enc_for_self