import json
import socket
import threading
from common.security import SecureChannel
from server.state import ServerState


class ClientSession(threading.Thread):
    """Handles the lifecycle of a single connected client."""

    def __init__(self, ch: SecureChannel, addr, state: ServerState):
        super().__init__(daemon=True)
        self.ch, self.addr, self.state = ch, addr, state
        self.username = None

    def run(self):
        try:
            while True:
                data = self.ch.recv()
                if not data:
                    break
                if self._dispatch(data) is False:
                    break
        finally:
            self._cleanup()

    def _dispatch(self, raw: bytes):
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_response(False, "ERRO mensagem invalida.")
            return

        if not isinstance(message, dict):
            self._send_response(False, "ERRO formato de mensagem invalido.")
            return

        handlers = {
            "REGISTER":       self._handle_register,
            "LOGIN":          self._handle_login,
            "LOGOUT":         self._handle_logout,
            "GET_CONTACTS":   self._handle_get_contacts,
            "ADD_CONTACT":    self._handle_add_contact,
            "REMOVE_CONTACT": self._handle_remove_contact,
            "SEND_MESSAGE":   self._handle_send_message,
            "FETCH_MESSAGES": self._handle_fetch_messages,
        }

        cmd = str(message.get("type", "")).strip().upper()
        handler = handlers.get(cmd)

        if handler:
            try:
                return handler(message)
            except TypeError:
                return handler()
        else:
            self._send_response(False, f"ERRO comando desconhecido: {cmd}")

    def _handle_login(self, payload: dict):
        user = str(payload.get("username", "")).strip()
        pwd = str(payload.get("password", ""))
        if not user or not pwd:
            return self._send_response(False, "ERRO username/password obrigatorios.")
        if self.username:
            return self._send_response(False, "ERRO ja autenticado.")
        if not self.state.authenticate_user(user, pwd):
            return self._send_response(False, "ERRO credenciais invalidas.")
        if not self.state.login_user(user, self):
            return self._send_response(False, "ERRO sessao ja ativa.")
        self.username = user
        print(f"  Login: {user}")
        self._send_response(True, f"OK bem-vindo, {user}!")

    def _handle_register(self, payload: dict):
        user = str(payload.get("username", "")).strip()
        pwd = str(payload.get("password", ""))
        if not user or not pwd:
            return self._send_response(False, "ERRO username/password obrigatorios.")
        if not self.state.register_user(user, pwd):
            return self._send_response(False, f"ERRO utilizador {user!r} ja existe.")
        print(f"  Registado: {user}")
        self._send_response(True, f"OK utilizador {user!r} registado.")

    def _handle_logout(self, message=None):
        name = self.username or "?"
        if self.username:
            self.state.logout_user(self.username)
            self.username = None
        self._send_response(True, f"OK ate logo, {name}!")

    def _handle_get_contacts(self, message=None):
        if not self._ensure_authenticated():
            return
        contacts = self.state.get_contacts(self.username)
        self._send_response(True, "OK lista de contactos.", {"contacts": contacts})

    def _handle_add_contact(self, payload: dict):
        if not self._ensure_authenticated():
            return
        contact = str(payload.get("contact", "")).strip()
        if not contact:
            return self._send_response(False, "ERRO contacto obrigatorio.")
        ok, message = self.state.add_contact(self.username, contact)
        self._send_response(ok, message)

    def _handle_remove_contact(self, payload: dict):
        if not self._ensure_authenticated():
            return
        contact = str(payload.get("contact", "")).strip()
        if not contact:
            return self._send_response(False, "ERRO contacto obrigatorio.")
        ok, message = self.state.remove_contact(self.username, contact)
        self._send_response(ok, message)

    def _handle_send_message(self, payload: dict):
        if not self._ensure_authenticated():
            return
        recipient = str(payload.get("to", "")).strip()
        content = str(payload.get("content", ""))
        if not recipient:
            return self._send_response(False, "ERRO destinatario obrigatorio.")
        if not content.strip():
            return self._send_response(False, "ERRO mensagem vazia.")
        contacts = self.state.get_contacts(self.username)
        if recipient not in contacts:
            return self._send_response(False, "ERRO so pode enviar mensagens para utilizadores na sua lista de contactos.")
        ok, message = self.state.queue_message(self.username, recipient, content)
        self._send_response(ok, message)

    def _handle_fetch_messages(self, payload: dict):
        if not self._ensure_authenticated():
            return
        contact_value = payload.get("contact")
        contact = None
        if isinstance(contact_value, str):
            contact = contact_value.strip() or None
        messages = self.state.pop_messages(self.username, contact)
        self._send_response(True, "OK mensagens obtidas.", {"messages": messages})

    def _ensure_authenticated(self) -> bool:
        if self.username:
            return True
        self._send_response(False, "ERRO autenticacao necessaria.")
        return False

    def _send_response(self, ok: bool, message: str, data: dict | None = None):
        payload = {"type": "RESPONSE", "ok": ok, "message": message}
        if data is not None:
            payload["data"] = data
        self.ch.send(json.dumps(payload).encode("utf-8"))

    def _cleanup(self):
        if self.username:
            self.state.logout_user(self.username)
            self.username = None
        self.ch.close()
        print(f"[-] {self.addr} desligou")


class ChatServer:
    def __init__(self, host, port, state):
        self.addr = (host, port)
        self.state = state
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self.sock.bind(self.addr)
        self.sock.listen()
        print(f"[*] Server listening on {self.addr}")
        try:
            while True:
                conn, addr = self.sock.accept()
                print(f"[+] Ligação de {addr} — a fazer handshake...")
                try:
                    ch = SecureChannel.server_handshake(conn)
                    print(f"    Canal seguro estabelecido com {addr}")
                except Exception as e:
                    print(f"    Handshake falhou com {addr}: {e}")
                    conn.close()
                    continue
                ClientSession(ch, addr, self.state).start()
        except KeyboardInterrupt:
            self.sock.close()