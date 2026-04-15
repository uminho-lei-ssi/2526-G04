import socket
import struct
import threading
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
configServer = config['SERVER']

HOST = configServer['address']
PORT = configServer.getint('port')

def send_msg(sock, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_msg(sock) -> bytes | None:
    header = _recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    return _recv_exact(sock, length)


def _recv_exact(sock, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_client(conn, addr):
    print(f"[+] Ligação de {addr}")
    try:
        while True:
            data = recv_msg(conn)
            if data is None:
                break
            print(f"[{addr}] {data.decode()}")
            send_msg(conn, b"OK")
    finally:
        conn.close()
        print(f"[-] {addr} desligou")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"Servidor em {HOST}:{PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()