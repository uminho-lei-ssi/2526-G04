import socket
import threading
import transport as tcp
from state import ServerState


# ---------------------------------------------------------------------------
# Handler de cada ligação de cliente
# ---------------------------------------------------------------------------

class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr, state: ServerState):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.state = state
        self.username: str | None = None

    def run(self):
        print(f"[+] Ligação de {self.addr}")
        try:
            while True:
                data = tcp.recv_msg(self.conn)
                if data is None:
                    break
                self._dispatch(data.decode())
        finally:
            self._cleanup()
            print(f"[-] {self.addr} desligou")

    # ------------------------------------------------------------------
    # Dispatcher — placeholder de texto simples, será JSON numa fase posterior
    # ------------------------------------------------------------------

    def _dispatch(self, text: str):
        parts = text.split(maxsplit=2)
        print(parts)
        if not parts:
            return

        cmd = parts[0].upper()

        if cmd == "REGISTER" and len(parts) == 3:
            self._handle_register(parts[1], parts[2])
        elif cmd == "LOGIN" and len(parts) == 3:
            self._handle_login(parts[1], parts[2])
        elif cmd == "LOGOUT":
            self._handle_logout()
        else:
            self._send(f"ERRO comando desconhecido: {cmd!r}")

    # ------------------------------------------------------------------
    # Comandos
    # ------------------------------------------------------------------

    def _handle_register(self, username: str, password: str):
        if not self.state.register_user(username, password):
            return self._send(f"ERRO utilizador {username!r} já existe.")
        print(f"  Registado: {username}")
        self._send(f"OK utilizador {username!r} registado.")

    def _handle_login(self, username: str, password: str):
        if self.username:
            return self._send("ERRO já autenticado.")
        if not self.state.authenticate_user(username, password):
            return self._send("ERRO credenciais inválidas.")
        if not self.state.login_user(username, self):
            return self._send("ERRO sessão já ativa.")
        self.username = username
        print(f"  Login: {username}")
        self._send(f"OK bem-vindo, {username}!")
        self._deliver_offline()

    def _handle_logout(self):
        name = self.username or "?"
        print(f"[-] Cliente desconectado em {self.addr} -> {name}")
        self._send(f"OK até logo, {name}!")
        self._cleanup()

    # ------------------------------------------------------------------
    # Entrega de mensagens offline acumuladas
    # ------------------------------------------------------------------

    def _deliver_offline(self):
        pending = self.state.get_offline_messages(self.username)
        for raw in pending:
            tcp.send_msg(self.conn, raw)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, text: str):
        tcp.send_msg(self.conn, text.encode())

    def _cleanup(self):
        if self.username:
            self.state.logout_user(self.username)
            self.username = None
        try:
            self.conn.close()
        except Exception:
            pass