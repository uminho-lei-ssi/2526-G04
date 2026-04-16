import socket
import struct
import sys

# ============= COMMON ============= #

def send_msg(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_msg(sock: socket.socket) -> bytes | None:
    header = _recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

