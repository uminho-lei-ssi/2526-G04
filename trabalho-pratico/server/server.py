import socket
import threading
import transport as comm
from state import ServerState

class ClientSession(threading.Thread):
    """Handles the lifecycle of a single connected client."""
    def __init__(self, conn, addr, state: ServerState):
        super().__init__(daemon=True)
        self.conn, self.addr, self.state = conn, addr, state
        self.username = None

    def run(self):
        try:
            while True:
                data = comm.recv_msg(self.conn)
                if not data: break
                if self._dispatch(data.decode()) is False:
                    break
        finally:
            self._cleanup()

    def _dispatch(self, text: str):
        # Keep this simple until you move to JSON
        parts = text.split(maxsplit=2)
        if not parts: return
        cmd = parts[0].upper()
        if cmd == "REGISTER" and len(parts) == 3:
            self._handle_register(parts[1], parts[2])
        elif cmd == "LOGIN" and len(parts) == 3:
            self._handle_login(parts[1], parts[2])
        elif cmd == "LOGOUT":
            return self._handle_logout()
        else:
            self._send(f"ERRO comando desconhecido: {cmd!r}".encode())

    def _handle_login(self, user, pwd):
        if self.username:
            return self._send(b"ERRO ja autenticado.")
        if not self.state.authenticate_user(user, pwd):
            return self._send(b"ERRO credenciais invalidas.")
        if not self.state.login_user(user, self):
            return self._send(b"ERRO sessao ja ativa.")
        self.username = user
        print(f"  Login: {user}")
        self._send(f"OK bem-vindo, {user}!".encode())

    def _cleanup(self):
        if self.username:
            self.state.logout_user(self.username)
            self.username = None
        try:
            self.conn.close()
        except Exception:
            pass
        print(f"[-] {self.addr} desligou")

    def _handle_register(self, user, pwd):
        if not self.state.register_user(user, pwd):
            return self._send(f"ERRO utilizador {user!r} já existe.".encode())
        print(f"  Registado: {user}")
        self._send(f"OK utilizador {user!r} registado.".encode())

    def _handle_logout(self):
        name = self.username or "?"
        print(f"[-] Cliente desconectado em {self.addr} -> {name}")
        self._send(f"OK até logo, {name}!".encode())
        if self.username:
            self.state.logout_user(self.username)
            self.username = None

    def _send(self, data: bytes):
        comm.send_msg(self.conn, data)

# ------------------------------------------------------------- #
# ------------------------------------------------------------- #

class ChatServer:
    """The main listener that accepts connections."""
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
                print(f"[+] Ligação de cliente em {addr}")
                ClientSession(conn, addr, self.state).start()
        except KeyboardInterrupt:
            self.sock.close()