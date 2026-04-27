import json
from common.security import SecureChannel


class ClientController:
    def __init__(self, ch: SecureChannel):
        self._ch = ch

    def login(self, username: str, password: str) -> tuple[bool, str]:
        ok, message, _ = self._request(
            {"type": "LOGIN", "username": username, "password": password}
        )
        return ok, message

    def register(self, username: str, password: str) -> tuple[bool, str]:
        ok, message, _ = self._request(
            {"type": "REGISTER", "username": username, "password": password}
        )
        return ok, message

    def logout(self) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "LOGOUT"})
        return ok, message

    def get_contacts(self) -> list[str]:
        ok, _, data = self._request({"type": "GET_CONTACTS"})
        if not ok:
            return []
        raw = data.get("contacts", [])
        return [c for c in raw if isinstance(c, str)]

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
        raw = data.get("messages", [])
        return [m for m in raw if isinstance(m, dict)]

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

        ok = bool(message.get("ok", False))
        text = str(message.get("message", "Sem mensagem."))
        data = message.get("data")
        if not isinstance(data, dict):
            data = {}
        return ok, text, data

    def disconnect(self):
        self._ch.close()