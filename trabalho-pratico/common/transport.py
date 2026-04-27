import socket
import struct

MAX_RAW_SIZE = 64 * 1024  # 64 KB limit to prevent DoS

# ============= COMMON ============= #

def send_raw(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_raw(sock: socket.socket) -> bytes | None:
    # Read the fixed-size length header first (first 4 bytes)
    header = recv_exact(sock, 4)
    if header is None: # caso a conexao feche por cliente sair por exemplo
        return None
    msg_len = int.from_bytes(header, "big")

    # Security Check: Validate length before allocating memory
    if msg_len > MAX_RAW_SIZE:
        # Close connection immediately - this is a protocol violation/attack
        sock.close()
        raise ValueError("Message too large!")

    data = recv_exact(sock, msg_len)
    return data


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ============= CLIENT ============= #

def connect(host: str, port: int) -> socket.socket | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock
    except ConnectionRefusedError:
        return None