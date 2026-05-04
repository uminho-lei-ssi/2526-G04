import json

from common.security import SecureChannel
from client import keystore


class ClientController:
    def __init__(self, ch: SecureChannel, keystore: keystore.KeyStore):
        self._ch = ch
        self._username: str | None = None
        self._priv_key = None  # Ed25519PrivateKey em memória após login
        self._keystore = keystore

    def register(self, username: str, password: str) -> tuple[bool, str]:
        # Gerar par de chaves localmente
        try:
            pub_b64, enc_priv_b64 = self._keystore.generate_and_save(username, password)
        except Exception as e:
            return False, f"Erro ao gerar chaves: {e}"

        ok, message, _ = self._request({
            "type":     "REGISTER",
            "username": username,
            "password": password,
            "pub_key":  pub_b64,
            "enc_priv": enc_priv_b64,
        })

        if not ok:
            # Reverter chaves locais se o servidor recusou
            self._keystore.delete_local_keys(username)

        return ok, message

    def login(self, username: str, password: str) -> tuple[bool, str]:
        ok, message, data = self._request({
            "type":     "LOGIN",
            "username": username,
            "password": password,
        })

        if not ok:
            return ok, message

        # Servidor devolveu as chaves — guardar/actualizar localmente e decifrar
        pub_b64      = data.get("pub_key", "")
        enc_priv_b64 = data.get("enc_priv", "")

        try:
            self._keystore.save_from_server(username, pub_b64, enc_priv_b64)
            self._priv_key = self._keystore.load_private_key(username, password)
        except ValueError as e:
            return False, f"Erro ao carregar chaves: {e}"

        self._username = username
        return ok, message

    def logout(self) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "LOGOUT"})
        if ok:
            if self._username:
                self._keystore.delete_local_keys(self._username)
            self._username = None
            self._priv_key = None
        return ok, message

    def get_contacts(self) -> list[str]:
        ok, _, data = self._request({"type": "GET_CONTACTS"})
        if not ok:
            return []
        return [c for c in data.get("contacts", []) if isinstance(c, str)]

    def add_contact(self, contact: str) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "ADD_CONTACT", "contact": contact})
        return ok, message

    def remove_contact(self, contact: str) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "REMOVE_CONTACT", "contact": contact})
        return ok, message

    def send_message(self, recipient: str, content: str) -> tuple[bool, str]:
        ok, message, _ = self._request(
            {"type": "SEND_MESSAGE", "to": recipient, "content": content}
        )
        return ok, message

    def fetch_messages(self, contact: str | None = None) -> list[dict]:
        payload: dict = {"type": "FETCH_MESSAGES"}
        if contact:
            payload["contact"] = contact
        ok, _, data = self._request(payload)
        if not ok:
            return []
        return [m for m in data.get("messages", []) if isinstance(m, dict)]

    def _request(self, payload: dict) -> tuple[bool, str, dict]:
        try:
            self._ch.send(json.dumps(payload).encode("utf-8"))
            resp = self._ch.recv()
        except OSError:
            return False, "Falha de comunicacao com o servidor.", {}

        if resp is None:
            return False, "Servidor desligou.", {}

        try:
            message = json.loads(resp.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "Resposta invalida do servidor.", {}

        if not isinstance(message, dict):
            return False, "Formato invalido de resposta.", {}

        ok   = bool(message.get("ok", False))
        text = str(message.get("message", "Sem mensagem."))
        data = message.get("data")
        if not isinstance(data, dict):
            data = {}
        return ok, text, data

    def disconnect(self):
        if self._username:
            self._keystore.delete_local_keys(self._username)
            self._username = None
            self._priv_key = None
        self._ch.close()