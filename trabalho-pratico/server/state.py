import base64
import json
import os
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.constant_time import bytes_eq


_STATE_PATH      = "server/data/server_state.json"


class ServerState:
    def __init__(self):

        self._users:        dict[str, dict]            = {}
        self._online:       dict[str, object]          = {}
        self._offline:      dict[str, list[dict]]      = {}
        self._contact_keys: dict[str, dict[str, str]]  = {}

        self._lock = threading.Lock()
        self._load_from_disk()

    # ------------------------------------------------------------------ #
    # API pública                                                         #
    # ------------------------------------------------------------------ #

    def register_user(self, username: str, password: str,
                      pub_key: str, blob: str,
                      cert: str = "", sig: str = "") -> bool:
        """
        Recebe a pub_key, o blob (salt + nonce + enc_seed) e o certificado CA.
        """
        with self._lock:
            if username in self._users:
                return False
            self._users[username] = {
                "password": self._hash_password(password),
                "pub_key":  pub_key,
                "blob":     blob,
                "cert":     cert,
                "sig":      sig,
                "contacts": set(),
            }
            self._offline[username]      = []
            self._contact_keys[username] = {}
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
        """Devolve a pub_key e o blob para o cliente sincronizar o cofre."""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            return {
                "pub_key": user.get("pub_key", ""), 
                "blob":    user.get("blob", "")
            }

    def get_pub_key(self, username: str) -> str | None:
        with self._lock:
            user = self._users.get(username)
            return user.get("pub_key") if user else None

    def get_cert(self, username: str) -> tuple[str, str] | None:
        """Devolve (cert_json, sig_b64) ou None se não existir."""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            cert = user.get("cert", "")
            sig  = user.get("sig", "")
            if not cert or not sig:
                return None
            return cert, sig

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
            return True, f"OK contacto adicionado."

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

    def store_contact_key(self, owner: str, contact: str, enc_key_owner: str, enc_key_contact: str, enc_username: str):
        """
        Armazena os pacotes para o handshake E2EE assíncrono.
        owner: quem está a adicionar (remetente)
        contact: quem está a ser adicionado (destinatário)
        """
        with self._lock:
            # para destino - ECDH + username cifrado
            self._contact_keys.setdefault(contact, {})[owner] = {
                "type": "ecdh",
                "key": enc_key_contact,
                "enc_username": enc_username
            }
            
            # para remetente - key cifrada para sincronizar novos dispositivos
            self._contact_keys.setdefault(owner, {})[contact] = {
                "type": "owner",
                "key": enc_key_owner,
                "enc_username": enc_username
            }
            self._persist_locked()

    def pop_contact_keys(self, username: str) -> dict[str, dict]:
        """
        Retorna as chaves de contactos registadas do user.
        """
        with self._lock:
            keys = dict(self._contact_keys.get(username, {}))
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

    def pop_messages(self, username: str, contact: str | None = None, last_id : int | None = None) -> list[dict]:
        """
        Retorna as mensagens guardadas no server para historico do cliente.
        Em caso de omissão de contacto, envia de todos.
        Em caso de omissão de last_id, envia todas as mensagens do contacto.
        """

        with self._lock:
            all_messages = self._offline.get(username, [])
            if not all_messages:
                return []

            cursor = last_id if last_id is not None else 0

            # filtrar as mensagens que o cliente ainda não viu com 'id' incremental (por implementar a 100%)
            selected = []
            for m in all_messages:
                id_match = m.get('id', 0) > cursor
                contact_match = (contact is None or m.get('from') == contact)
                
                if id_match and contact_match:
                    selected.append(m)

            # Neste momento, persiste-se tudo
            self._persist_locked()

            return selected

    # ------------------------------------------------------------------ #
    # Persistência                                                       #
    # ------------------------------------------------------------------ #

    def _persist_locked(self):
        """Grava o estado diretamente em JSON."""
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
        
        # conversao para lista para permitir serializar em JSON
        users_serial = {
            uname: {**u, "contacts": list(u.get("contacts", []))}
            for uname, u in self._users.items()
        }

        state_data = {
            "users":        users_serial,
            "offline":      self._offline,
            "contact_keys": self._contact_keys,
        }
        try:
            with open(_STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(state_data, f, indent=4, ensure_ascii=False)
        except OSError as e:
            print(f"[-] Erro ao persistir estado em disco: {e}")

    def _load_from_disk(self):
        """Carrega o estado a partir do ficheiro JSON plaintext."""
        if not os.path.exists(_STATE_PATH):
            return

        try:
            with open(_STATE_PATH, "r", encoding="utf-8") as f:
                state_data = json.load(f)
                
            # conversao para set para deteção agilizada de dups
            self._users = {
                uname: {**u, "contacts": set(u.get("contacts", []))}
                for uname, u in state_data.get("users", {}).items()
            }
            self._offline      = state_data.get("offline", {})
            self._contact_keys = state_data.get("contact_keys", {})
        except (OSError, json.JSONDecodeError) as e:
            print(f"[-] Erro ao carregar estado: {e}. A iniciar base de dados limpa.")
            self._users, self._offline, self._contact_keys = {}, {}, {}


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
    