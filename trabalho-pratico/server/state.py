import base64
import hashlib
import hmac
import json
import os
import threading
import time


class ServerState:
    """Manages the server state: users, online sessions and offline messages."""

    def __init__(self, data_path: str | None = None):
        if data_path is None:
            root = os.path.dirname(os.path.dirname(__file__))
            data_path = os.path.join(root, "data", "server_state.json")

        self._data_path = data_path

        # { username: { "password": dict|str, "contacts": set[str] } }
        self._users: dict[str, dict] = {}
        # { username: handler_thread }
        self._online: dict[str, object] = {}
        # { username: [ {"from": str, "content": str, "ts": int }, ... ] }
        self._offline: dict[str, list[dict]] = {}

        self._lock = threading.Lock()
        self._load_from_disk()

    def register_user(self, username: str, password: str) -> bool:
        with self._lock:
            if username in self._users:
                return False

            self._users[username] = {
                "password": self._hash_password(password),
                "contacts": set(),
            }
            self._offline[username] = []
            self._persist_locked()
            return True

    def authenticate_user(self, username: str, password: str) -> bool:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                return False

            stored = user.get("password")

            # Backward compatibility for old plaintext states.
            if isinstance(stored, str):
                ok = stored == password
                if ok:
                    user["password"] = self._hash_password(password)
                    self._persist_locked()
                return ok

            if not isinstance(stored, dict):
                return False

            return self._verify_password(password, stored)

    def login_user(self, username: str, handler) -> bool:
        with self._lock:
            if username in self._online:
                print("User is already logged in.")
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

    def get_offline_messages(self, username: str) -> list[dict]:
        with self._lock:
            messages = self._offline.get(username, [])
            self._offline[username] = []
            self._persist_locked()
            return messages

    def add_offline_message(self, username: str, message: dict):
        with self._lock:
            if username in self._offline:
                self._offline[username].append(message)
                self._persist_locked()

    def queue_message(self, sender: str, recipient: str, content: str) -> tuple[bool, str]:
        with self._lock:
            if sender not in self._users:
                return False, "ERRO remetente invalido."
            if recipient not in self._users:
                return False, "ERRO destinatario nao existe."
            if not content:
                return False, "ERRO mensagem vazia."

            self._offline[recipient].append(
                {
                    "from": sender,
                    "content": content,
                    "ts": int(time.time()),
                }
            )
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

            selected: list[dict] = []
            remaining: list[dict] = []
            for item in queue:
                if item.get("from") == contact:
                    selected.append(item)
                else:
                    remaining.append(item)

            self._offline[username] = remaining
            self._persist_locked()
            return selected

    def _persist_locked(self):
        os.makedirs(os.path.dirname(self._data_path), exist_ok=True)

        serializable_users: dict[str, dict] = {}
        for username, user_data in self._users.items():
            serializable_users[username] = {
                "password": user_data.get("password"),
                "contacts": sorted(user_data.get("contacts", set()), key=str.lower),
            }

        payload = {
            "users": serializable_users,
            "offline": self._offline,
        }

        with open(self._data_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def _load_from_disk(self):
        if not os.path.exists(self._data_path):
            return

        try:
            with open(self._data_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        users = payload.get("users", {})
        offline = payload.get("offline", {})
        if not isinstance(users, dict) or not isinstance(offline, dict):
            return

        loaded_users: dict[str, dict] = {}
        loaded_offline: dict[str, list[dict]] = {}

        for username, user_data in users.items():
            if not isinstance(username, str) or not isinstance(user_data, dict):
                continue

            contacts_raw = user_data.get("contacts", [])
            if isinstance(contacts_raw, list):
                contacts = {c for c in contacts_raw if isinstance(c, str)}
            else:
                contacts = set()

            loaded_users[username] = {
                "password": user_data.get("password", ""),
                "contacts": contacts,
            }

        for username, messages in offline.items():
            if not isinstance(username, str) or not isinstance(messages, list):
                continue
            valid_messages = [m for m in messages if isinstance(m, dict)]
            loaded_offline[username] = valid_messages

        self._users = loaded_users
        self._offline = loaded_offline
        for username in self._users:
            self._offline.setdefault(username, [])

    def _hash_password(self, password: str) -> dict:
        salt = os.urandom(16)
        iterations = 150_000
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return {
            "algorithm": "pbkdf2-sha256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": base64.b64encode(digest).decode("ascii"),
        }

    def _verify_password(self, password: str, stored: dict) -> bool:
        if stored.get("algorithm") != "pbkdf2-sha256":
            return False

        iterations = stored.get("iterations")
        salt_b64 = stored.get("salt")
        hash_b64 = stored.get("hash")
        if not isinstance(iterations, int):
            return False
        if not isinstance(salt_b64, str) or not isinstance(hash_b64, str):
            return False

        try:
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
        except (ValueError, TypeError):
            return False

        got = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(got, expected)