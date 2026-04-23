import json
import socket
import transport as tcp


class ClientController:
    def __init__(self, sock: socket.socket):
        self._sock = sock

    # ------------------------------------------------------------------
    # Acoes chamadas pelo UI — return (ok: bool, message: str)
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> tuple[bool, str]:
        ok, message, _ = self._request(
            {"type": "login", "username": username, "password": password}
        )
        return ok, message

    def register(self, username: str, password: str) -> tuple[bool, str]:
        ok, message, _ = self._request(
            {"type": "register", "username": username, "password": password}
        )
        return ok, message

    def logout(self) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "logout"})
        return ok, message

    def get_contacts(self) -> list[str]:
        ok, _, data = self._request({"type": "get_contacts"})
        if not ok:
            return []

        raw_contacts = data.get("contacts", [])
        if not isinstance(raw_contacts, list):
            return []

        return [contact for contact in raw_contacts if isinstance(contact, str)]

    def add_contact(self, contact: str) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "add_contact", "contact": contact})
        return ok, message

    def remove_contact(self, contact: str) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "remove_contact", "contact": contact})
        return ok, message

    def send_message(self, recipient: str, content: str) -> tuple[bool, str]:
        ok, message, _ = self._request(
            {
                "type": "send_message",
                "to": recipient,
                "content": content,
            }
        )
        return ok, message

    def fetch_messages(self, contact: str | None = None) -> list[dict]:
        payload: dict = {"type": "fetch_messages"}
        if contact:
            payload["contact"] = contact

        ok, _, data = self._request(payload)
        if not ok:
            return []

        raw_messages = data.get("messages", [])
        if not isinstance(raw_messages, list):
            return []

        messages: list[dict] = []
        for item in raw_messages:
            if isinstance(item, dict):
                messages.append(item)
        return messages

    def _request(self, payload: dict) -> tuple[bool, str, dict]:
        try:
            tcp.send_msg(self._sock, json.dumps(payload).encode("utf-8"))
            resp = tcp.recv_msg(self._sock)
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
        self._sock.close()