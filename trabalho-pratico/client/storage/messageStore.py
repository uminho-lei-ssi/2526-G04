"""
client/message_store.py — Histórico local de mensagens por conversa.

Cada conversa é guardada em: <messages_dir>/<username>_<contact>.json
Formato:
[
  { "from": "alice", "content": "<ciphertext_b64>", "ts": 1234567890 },
  ...
]

O conteúdo é cifrado com a chave simétrica da conversa (AES-256-GCM).
O servidor nunca vê o plaintext.
"""

import base64
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessageStore:
    def __init__(self, messages_dir: str):
        self.messages_dir = os.path.abspath(messages_dir)

    def _conv_path(self, username: str, contact: str) -> str:
        a, b = sorted([username, contact])
        return os.path.join(self.messages_dir, f"{a}_{b}.json")

    def _load(self, username: str, contact: str) -> list[dict]:
        path = self._conv_path(username, contact)
        if not os.path.exists(path):
            return []
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    def _save(self, username: str, contact: str, messages: list[dict]):
        os.makedirs(self.messages_dir, exist_ok=True)
        with open(self._conv_path(username, contact), "w") as f:
            json.dump(messages, f, indent=2)

    def append_ciphered(self, username: str, contact: str,
               sender: str, plaintext: str, sym_key: bytes, ts: int | None = None):
        """Cifra `plaintext` com `sym_key` e acrescenta ao histórico local."""
        nonce = os.urandom(12)
        ct    = AESGCM(sym_key).encrypt(nonce, plaintext.encode(), None)
        entry = {
            "from":    sender,
            "content": base64.b64encode(nonce + ct).decode(),
            "ts":      ts or int(time.time()),
        }
        messages = self._load(username, contact)
        messages.append(entry)
        self._save(username, contact, messages)

    def load_all(self, username: str, contact: str, sym_key: bytes) -> list[dict]:
        """Devolve todas as mensagens da conversa decifradas, ordenadas por timestamp."""
        raw = self._load(username, contact)
        result = []
        for entry in raw:
            try:
                blob  = base64.b64decode(entry["content"])
                nonce, ct = blob[:12], blob[12:]
                text  = AESGCM(sym_key).decrypt(nonce, ct, None).decode()
                result.append({
                    "from":    entry["from"],
                    "content": text,
                    "ts":      entry.get("ts", 0),
                })
            except Exception:
                continue
        return sorted(result, key=lambda m: m["ts"])
    
    # ------------------------------------------------------------------ #
    # Cifra/decifra — usados pelo controller e pelo send/fetch           #
    # ------------------------------------------------------------------ #
 
    @staticmethod
    def encrypt_message(plaintext: str, sym_key: bytes) -> str:
        """Cifra plaintext com AES-256-GCM. Devolve base64(nonce + ciphertext)."""
        nonce = os.urandom(12)
        ct    = AESGCM(sym_key).encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()
 
    @staticmethod
    def decrypt_message(ciphertext_b64: str, sym_key: bytes) -> str | None:
        """Decifra um blob base64(nonce + ciphertext). Devolve None se falhar."""
        try:
            raw        = base64.b64decode(ciphertext_b64)
            nonce, ct  = raw[:12], raw[12:]
            return AESGCM(sym_key).decrypt(nonce, ct, None).decode()
        except Exception:
            return None