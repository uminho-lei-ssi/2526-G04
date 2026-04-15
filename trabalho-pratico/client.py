import socket
import struct
import sys
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


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Erro: servidor não encontrado.")
        sys.exit(1)

    print("Ligado. Escreve mensagens (Ctrl+C para sair).")
    try:
        while True:
            line = input("> ")
            if not line:
                continue
            send_msg(sock, line.encode())
            resp = recv_msg(sock)
            if resp is None:
                print("Servidor desligou.")
                break
            print(f"Servidor: {resp.decode()}")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()