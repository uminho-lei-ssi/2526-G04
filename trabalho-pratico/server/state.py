import base64
import json
import os
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.constant_time import bytes_eq


_STATE_PATH      = "server/data/server_state.bin"
_MASTER_KEY_PATH = "server/data/.master_key"


class ServerState:
    def __init__(self):
        self._master_key = self._load_or_generate_master_key()

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

    def store_contact_key(self, recipient: str, sender: str, enc_key_owner: str, enc_key_target: str):
        with self._lock:
            self._contact_keys.setdefault(sender, {})[recipient] = enc_key_owner
            self._contact_keys.setdefault(recipient, {})[sender] = enc_key_target
            self._persist_locked()

    # chaves permanecem cifradas no servidor, na mesma logica que o par de chaves pessoal protegido
    def pop_contact_keys(self, username: str) -> dict[str, str]:
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

            # Filtrar as mensagens que o cliente ainda não viu
            # Usamos o campo 'id' como um inteiro incremental
            selected = []
            for m in all_messages:
                id_match = m.get('id', 0) > cursor
                contact_match = (contact is None or m.get('from') == contact)
                
                if id_match and contact_match:
                    selected.append(m)

            # Neste momento, persiste-se tudo
            self._persist_locked()

            return selected
        
        with self._lock:
            messages = self._offline.get(username, [])
            if last_id is None: last_id = 0
            if contact is None:
                return [m for m in messages if m['id'] > float(last_id)]
            
            return [m for m in messages if m['ts'] > float(last_id)]
    
        with self._lock:
            messages = self._offline.get(username, [])
            if not messages:
                return []
            if contact is None:
                self._offline[username] = []
                self._persist_locked()
                return list(messages)
            selected, remaining = [], []
            for item in queue:
                (selected if item.get("from") == contact else remaining).append(item)
            self._offline[username] = remaining
            self._persist_locked()
            return selected

    # ------------------------------------------------------------------ #
    # Persistência cifrada                                               #
    # ------------------------------------------------------------------ #

    def _load_or_generate_master_key(self) -> bytes:
        """
        Carrega ou gera a chave mestre do servidor (32 bytes aleatórios).
        Usada para cifrar o ficheiro de estado em repouso com AES-256-GCM.
        """
        os.makedirs(os.path.dirname(_MASTER_KEY_PATH), exist_ok=True)
        if os.path.exists(_MASTER_KEY_PATH):
            with open(_MASTER_KEY_PATH, "rb") as f:
                key = f.read()
            if len(key) == 32:
                return key
        key = os.urandom(32)
        with open(_MASTER_KEY_PATH, "wb") as f:
            f.write(key)
        print(f"[*] Chave mestre do servidor gerada em {_MASTER_KEY_PATH!r}.")
        return key

    def _persist_locked(self):
        """Serializa e cifra o estado completo com AES-256-GCM."""
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)

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
                {"from": m["from"], "content": m["content"], "ts": m["ts"]}
                for m in messages
            ]

        json_bytes = json.dumps({
            "users":        serializable_users,
            "offline":      serializable_offline,
            "contact_keys": self._contact_keys,
        }, ensure_ascii=False).encode("utf-8")

        nonce      = os.urandom(12)
        ciphertext = AESGCM(self._master_key).encrypt(nonce, json_bytes, None)

        with open(_STATE_PATH, "wb") as f:
            f.write(nonce + ciphertext)

    def _load_from_disk(self):
        legacy_path = "server/data/server_state.json"

        # Tentar carregar estado cifrado
        if os.path.exists(_STATE_PATH):
            try:
                with open(_STATE_PATH, "rb") as f:
                    raw = f.read()
                if len(raw) < 12:
                    return
                nonce, ct  = raw[:12], raw[12:]
                json_bytes = AESGCM(self._master_key).decrypt(nonce, ct, None)
                payload    = json.loads(json_bytes.decode("utf-8"))
            except Exception as e:
                print(f"[!] Erro ao carregar estado cifrado: {e}")
                return
            self._deserialize(payload)
            return

        # Migrar estado legado em JSON (plaintext)
        if os.path.exists(legacy_path):
            print(f"[*] Estado legado encontrado — a migrar para formato cifrado...")
            try:
                with open(legacy_path, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                self._deserialize(payload)
                self._persist_locked()
                os.rename(legacy_path, legacy_path + ".migrated")
                print(f"[*] Migração concluída.")
            except Exception as e:
                print(f"[!] Erro na migração: {e}")

    def _deserialize(self, payload: dict):
        users        = payload.get("users", {})
        offline      = payload.get("offline", {})
        contact_keys = payload.get("contact_keys", {})

        if not isinstance(users, dict) or not isinstance(offline, dict):
            return

        for username, u in users.items():
            if not isinstance(username, str) or not isinstance(u, dict):
                continue
            contacts_raw = u.get("contacts", [])
            contacts = {c for c in contacts_raw if isinstance(c, str)} \
                       if isinstance(contacts_raw, list) else set()
            self._users[username] = {
                "password": u.get("password", ""),
                "pub_key":  u.get("pub_key", ""),
                "enc_priv": u.get("enc_priv", ""),
                "contacts": contacts,
            }

        for username, messages in offline.items():
            if not isinstance(username, str) or not isinstance(messages, list):
                continue
            res = []
            for m in messages:
                if not isinstance(m, dict):
                    continue
                try:
                    res.append({"from": m["from"], "content": m["content"], "ts": m["ts"]})
                except KeyError:
                    continue
            self._offline[username] = res

        for username in self._users:
            self._offline.setdefault(username, [])

        for username, keys in contact_keys.items():
            if isinstance(keys, dict):
                self._contact_keys[username] = keys
        for username in self._users:
            self._contact_keys.setdefault(username, {})

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