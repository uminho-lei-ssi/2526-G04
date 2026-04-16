import socket
import struct

def connect(host: str, port: int) -> socket.socket | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock
    except ConnectionRefusedError:
        return None

def send_msg(sock: socket.socket, data: bytes):
    """Prefixes message with 4-byte length header."""
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_msg(sock: socket.socket) -> bytes | None:
    """Reads length header then returns the full payload."""
    header = _recv_exact(sock, 4)
    if not header: return None
    (length,) = struct.unpack("!I", header)
    return _recv_exact(sock, length)

def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: return None
        buf += chunk
    return buf