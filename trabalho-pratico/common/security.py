import os
import socket
import common.transport as tcp
 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256


class SecureChannel:
    """
    Canal que mantém apenas o handshake X25519, mas transmite as mensagens em texto simples.
    """
 
    def __init__(self, sock: socket.socket, keyLength: bytes):
        """
        Não instanciar directamente — usar client_handshake / server_handshake.
        key: 32 bytes derivados via HKDF (utilizados apenas no handshake).
        """
        self._sock = sock
        self._key = keyLength
 
    # -------------------------------------------------------------- #
    # Handshake                                                       #
    # -------------------------------------------------------------- #
 
    @classmethod
    def server_handshake(cls, sock: socket.socket) -> "SecureChannel":
        """
        Servidor:
          1. Gera par efémero X25519
          2. Recebe chave pública do cliente
          3. Envia a sua chave pública
          4. Deriva chave de sessão via HKDF
        """
        # Gerar par efemero
        privKey = X25519PrivateKey.generate()
        pub_bytes = privKey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
 
        # Receber pubKey do cliente, enviar a nossa
        client_pub_bytes = tcp.recv_raw(sock)
        if not client_pub_bytes or len(client_pub_bytes) != 32:
            raise ConnectionError("Handshake falhou: chave pública do cliente inválida.")
        tcp.send_raw(sock, pub_bytes)
 
        # Calcular segredo partilhado
        client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = privKey.exchange(client_pub)
 
        # Derivar chave AES-256 — o contexto "chat-session-key" é um label
        # arbitrário que garante que esta chave só é usada para este fim
        key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"chat-session-key",
        ).derive(shared_secret)
 
        return cls(sock, key)
 
    @classmethod
    def client_handshake(cls, sock: socket.socket) -> "SecureChannel":
        """
        Cliente:
          1. Gera par efémero X25519
          2. Envia a sua chave pública
          3. Recebe chave pública do servidor
          4. Deriva a mesma chave de sessão via HKDF
        """
        privKey= X25519PrivateKey.generate()
        pub_bytes = privKey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
 
        # Enviar a nossa pubKey, receber a do servidor
        tcp.send_raw(sock, pub_bytes)
        server_pub_bytes = tcp.recv_raw(sock)
        if not server_pub_bytes or len(server_pub_bytes) != 32:
            raise ConnectionError("Handshake falhou: chave pública do servidor inválida.")
 
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared_secret = privKey.exchange(server_pub)
 
        key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"chat-session-key",
        ).derive(shared_secret)
 
        return cls(sock, key)
 
    # -------------------------------------------------------------- #
    # Envio e recepção simples                                         #
    # -------------------------------------------------------------- #

    def send(self, data: bytes):
        """Envia `data` em texto simples, usando o protocolo de comprimento do transporte."""
        tcp.send_raw(self._sock, data)

    def recv(self) -> bytes | None:
        """Recebe uma mensagem em texto simples. Devolve None se a ligação fechou."""
        return tcp.recv_raw(self._sock)
 
    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass
 
 