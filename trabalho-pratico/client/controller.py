import socket
import transport as tcp


class ClientController:
    def __init__(self, sock: socket.socket):
        self._sock = sock

    # ------------------------------------------------------------------
    # Acoes chamadas pelo UI — return (ok: bool, message: str)
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> tuple[bool, str]:
        # placeholder — will be replaced by structured messages
        tcp.send_msg(self._sock, f"LOGIN {username} {password}".encode())
        resp = tcp.recv_msg(self._sock)
        if resp is None:
            return False, "Servidor desligou."
        return True, resp.decode()

    def register(self, username: str, password: str) -> tuple[bool, str]:
        # placeholder — will be replaced by structured messages
        tcp.send_msg(self._sock, f"REGISTER {username} {password}".encode())
        resp = tcp.recv_msg(self._sock)
        if resp is None:
            return False, "Servidor desligou."
        return True, resp.decode()

    def logout(self) -> tuple[bool, str]:
        tcp.send_msg(self._sock, b"LOGOUT")
        resp = tcp.recv_msg(self._sock)
        if resp is None:
            return False, "Servidor desligou."
        return True, resp.decode()

    def get_contacts(self) -> list[str]:
        # TODO -> placeholder — will be fetched from server
        return ["Carlos", "Ana", "Bruno", "Diana"]

    def disconnect(self):
        self._sock.close()