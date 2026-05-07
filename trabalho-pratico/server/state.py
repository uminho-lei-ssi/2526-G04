import base64
import json
import os
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.constant_time import bytes_eq


class ServerState:
    def __init__(self):
        self._data_path   = "server/data/server_state.json"
        self._key_path    = os.path.join(os.path.dirname(self._data_path), "storage.key")
        self._storage_key = self._load_or_create_key()

        self._users:        dict[str, dict]            = {}
        self._online:       dict[str, object]          = {}
        self._offline:      dict[str, list[dict]]      = {}
        self._pending_keys: dict[str, dict[str, str]]  = {}

        self._lock = threading.Lock()
        self._load_from_disk()

    # ------------------------------------------------------------------ #
    # Chave de armazenamento offline                                      #
    # ------------------------------------------------------------------ #

    def _load_or_create_key(self) -> bytes:
        os.makedirs(os.path.dirname(self._key_path), exist_ok=True)
        if os.path.exists(self._key_path):
            with open(self._key_path, "rb") as f:
                return f.read()
        key = os.urandom(32)
        with open(self._key_path, "wb") as f:
            f.write(key)
        return key

    def _encrypt_message(self, content: str) -> str:
        nonce = os.urandom(12)
        ct    = AESGCM(self._storage_key).encrypt(nonce, content.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def _decrypt_message(self, encrypted: str) -> str:
        raw        = base64.b64decode(encrypted)
        nonce, ct  = raw[:12], raw[12:]
        return AESGCM(self._storage_key).decrypt(nonce, ct, None).decode()

    # ------------------------------------------------------------------ #
    # API pública                                                         #
    # ------------------------------------------------------------------ #

    def register_user(self, username: str, password: str,
                      pub_key: str, enc_priv: str) -> bool:
        with self._lock:
            if username in self._users:
                return False
            self._users[username] = {
                "password": self._hash_password(password),
                "pub_key":  pub_key,
                "enc_priv": enc_priv,
                "contacts": set(),
            }
            self._offline[username]      = []
            self._pending_keys[username] = {}
            self._persist_locked()
            return True

    def authenticate_user(self, username: str, password: str) -> bool:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                return False
            stored = user.get("password")
            if not isinstance(stored, dict):
                return False
            return self._verify_password(password, stored)

    def get_key_bundle(self, username: str) -> dict | None:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            return {"pub_key": user.get("pub_key", ""), "enc_priv": user.get("enc_priv", "")}

    def get_pub_key(self, username: str) -> str | None:
        with self._lock:
            user = self._users.get(username)
            return user.get("pub_key") if user else None

    def login_user(self, username: str, handler) -> bool:
        with self._lock:
            if username in self._online:
                return False
            self._online[username] = handler
            return True

    def logout_user(self, username: str):
        with self._lock:
            self._online.pop(username, None)

    def user_exists(self, username: str) -> bool:
        with self._lock:
            return username in self._users

    def get_contacts(self, username: str) -> list[str]:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return []
            return sorted(user["contacts"], key=str.lower)

    def add_contact(self, owner: str, contact: str) -> tuple[bool, str]:
        with self._lock:
            if owner not in self._users:
                return False, "ERRO utilizador nao autenticado."
            if contact not in self._users:
                return False, "ERRO contacto nao existe."
            if owner == contact:
                return False, "ERRO nao pode adicionar-se a si mesmo."
            contacts = self._users[owner]["contacts"]
            if contact in contacts:
                return False, "ERRO contacto ja existe na lista."
            contacts.add(contact)
            self._persist_locked()
            return True, f"OK contacto {contact!r} adicionado."

    def remove_contact(self, owner: str, contact: str) -> tuple[bool, str]:
        with self._lock:
            if owner not in self._users:
                return False, "ERRO utilizador nao autenticado."
            contacts = self._users[owner]["contacts"]
            if contact not in contacts:
                return False, "ERRO contacto nao encontrado."
            contacts.remove(contact)
            self._persist_locked()
            return True, f"OK contacto {contact!r} removido."

    def store_pending_key(self, recipient: str, sender: str, enc_key_blob: str):
        with self._lock:
            self._pending_keys.setdefault(recipient, {})[sender] = enc_key_blob
            self._persist_locked()

    def pop_pending_keys(self, username: str) -> dict[str, str]:
        with self._lock:
            keys = dict(self._pending_keys.get(username, {}))
            self._pending_keys[username] = {}
            if keys:
                self._persist_locked()
            return keys

    def queue_message(self, sender: str, recipient: str, content: str) -> tuple[bool, str]:
        with self._lock:
            if sender not in self._users:
                return False, "ERRO remetente invalido."
            if recipient not in self._users:
                return False, "ERRO destinatario nao existe."
            if not content:
                return False, "ERRO mensagem vazia."
            self._offline[recipient].append({
                "from": sender, "content": content, "ts": int(time.time()),
            })
            self._persist_locked()
            return True, "OK mensagem enfileirada."

    def pop_messages(self, username: str, contact: str | None = None) -> list[dict]:
        with self._lock:
            queue = self._offline.get(username, [])
            if not queue:
                return []
            if contact is None:
                self._offline[username] = []
                self._persist_locked()
                return list(queue)
            selected, remaining = [], []
            for item in queue:
                (selected if item.get("from") == contact else remaining).append(item)
            self._offline[username] = remaining
            self._persist_locked()
            return selected

    # ------------------------------------------------------------------ #
    # Persistência                                                        #
    # ------------------------------------------------------------------ #

    def _persist_locked(self):
        os.makedirs(os.path.dirname(self._data_path), exist_ok=True)

        serializable_users = {}
        for username, u in self._users.items():
            serializable_users[username] = {
                "password": u.get("password"),
                "pub_key":  u.get("pub_key", ""),
                "enc_priv": u.get("enc_priv", ""),
                "contacts": sorted(u.get("contacts", set()), key=str.lower),
            }

        serializable_offline = {}
        for username, messages in self._offline.items():
            serializable_offline[username] = [
                {"from": m["from"], "content": self._encrypt_message(m["content"]), "ts": m["ts"]}
                for m in messages
            ]

        with open(self._data_path, "w", encoding="utf-8") as f:
            json.dump({
                "users":        serializable_users,
                "offline":      serializable_offline,
                "pending_keys": self._pending_keys,
            }, f, ensure_ascii=False, indent=2)

    def _load_from_disk(self):
        if not os.path.exists(self._data_path):
            return
        try:
            with open(self._data_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        users        = payload.get("users", {})
        offline      = payload.get("offline", {})
        pending_keys = payload.get("pending_keys", {})

        if not isinstance(users, dict) or not isinstance(offline, dict):
            return

        for username, u in users.items():
            if not isinstance(username, str) or not isinstance(u, dict):
                continue
            contacts_raw = u.get("contacts", [])
            contacts = {c for c in contacts_raw if isinstance(c, str)} if isinstance(contacts_raw, list) else set()
            self._users[username] = {
                "password": u.get("password", ""),
                "pub_key":  u.get("pub_key", ""),
                "enc_priv": u.get("enc_priv", ""),
                "contacts": contacts,
            }

        for username, messages in offline.items():
            if not isinstance(username, str) or not isinstance(messages, list):
                continue
            decrypted = []
            for m in messages:
                if not isinstance(m, dict):
                    continue
                try:
                    content = self._decrypt_message(m["content"])
                except Exception:
                    continue
                decrypted.append({"from": m["from"], "content": content, "ts": m["ts"]})
            self._offline[username] = decrypted

        for username in self._users:
            self._offline.setdefault(username, [])

        for username, keys in pending_keys.items():
            if isinstance(keys, dict):
                self._pending_keys[username] = keys
        for username in self._users:
            self._pending_keys.setdefault(username, {})

    # ------------------------------------------------------------------ #
    # Passwords                                                           #
    # ------------------------------------------------------------------ #

    def _hash_password(self, password: str) -> dict:
        salt = os.urandom(16)
        iterations = 150_000
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        digest = kdf.derive(password.encode())
        return {
            "algorithm":  "pbkdf2-sha256",
            "iterations": iterations,
            "salt":       base64.b64encode(salt).decode(),
            "hash":       base64.b64encode(digest).decode(),
        }

    def _verify_password(self, password: str, stored: dict) -> bool:
        if stored.get("algorithm") != "pbkdf2-sha256":
            return False
        iterations = stored.get("iterations")
        salt_b64   = stored.get("salt")
        hash_b64   = stored.get("hash")
        if not isinstance(iterations, int) or not isinstance(salt_b64, str) or not isinstance(hash_b64, str):
            return False
        try:
            salt     = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
        except (ValueError, TypeError):
            return False
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        got = kdf.derive(password.encode())
        return bytes_eq(got, expected)