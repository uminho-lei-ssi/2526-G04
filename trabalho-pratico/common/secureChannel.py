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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12  # 96 bits - tamanho recomendado para AES-GCM


class SecureChannel:
    """
    Canal seguro server-client com handshake X25519 + encriptação AES-256-GCM por mensagem.
    Cada mensagem tem um nonce aleatório de 12 bytes prefixado ao ciphertext.
    """
 
    def __init__(self, sock: socket.socket, key: bytes):
        """
        Não instanciar directamente — usar client_handshake / server_handshake.
        key: 32 bytes derivados via HKDF, usados para AES-256-GCM.
        """
        self._sock = sock
        self._aesgcm = AESGCM(key)
 
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
        privKey = X25519PrivateKey.generate()
        pub_bytes = privKey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
 
        client_pub_bytes = tcp.recv_raw(sock)
        if not client_pub_bytes or len(client_pub_bytes) != 32:
            raise ConnectionError("Handshake falhou: chave pública do cliente inválida.")
        tcp.send_raw(sock, pub_bytes)
 
        client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = privKey.exchange(client_pub)
 
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
        privKey = X25519PrivateKey.generate()
        pub_bytes = privKey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
 
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
    # Envio e recepção com AES-256-GCM                                #
    # -------------------------------------------------------------- #

    def send(self, data: bytes):
        """
        Encripta `data` com AES-256-GCM usando um nonce aleatório e envia:
            [ 12 bytes nonce ][ ciphertext + 16 bytes tag GCM ]
        """
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        tcp.send_raw(self._sock, nonce + ciphertext)

    def recv(self) -> bytes | None:
        """
        Recebe uma mensagem, verifica a tag GCM e desencripta.
        Devolve None se a ligação fechou.
        Lança ValueError se a autenticação falhar (mensagem corrompida/adulterada).
        """
        raw = tcp.recv_raw(self._sock)
        if raw is None:
            return None

        if len(raw) < NONCE_SIZE:
            raise ValueError("Mensagem demasiado curta para conter nonce.")

        nonce = raw[:NONCE_SIZE]
        ciphertext = raw[NONCE_SIZE:]

        # AESGCM.decrypt lança InvalidTag se a autenticação falhar
        return self._aesgcm.decrypt(nonce, ciphertext, None)
 
    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass