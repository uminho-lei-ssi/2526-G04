import os
import socket
import threading
import common.transport as tcp

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12

# Tamanhos do handshake autenticado
_ED25519_PUB_SIZE  = 32   # chave pública Ed25519 raw
_X25519_PUB_SIZE   = 32   # chave pública X25519 raw
_ED25519_SIG_SIZE  = 64   # assinatura Ed25519
# Total enviado pelo servidor: signing_pub[32] + eph_pub[32] + sig[64] = 128 bytes
_SERVER_HELLO_SIZE = _ED25519_PUB_SIZE + _X25519_PUB_SIZE + _ED25519_SIG_SIZE


class SecureChannel:
    """
    Canal seguro autenticado cliente-servidor.

    Handshake:
      C → S : eph_pub_client  (32 bytes X25519)
      S → C : server_signing_pub (32 bytes Ed25519)
              + eph_pub_server  (32 bytes X25519)
              + sig(server_signing_priv, eph_pub_server) (64 bytes Ed25519)

    O cliente verifica a assinatura com a chave pública de longa duração do
    servidor (TOFU na primeira ligação, verificação nas seguintes).
    Ambos derivam a chave de sessão via HKDF(X25519(eph_priv, peer_pub)).

    Cada mensagem: [ 12 bytes nonce ][ ciphertext + 16 bytes tag GCM ]
    send() é thread-safe (lock interno).
    """

    def __init__(self, sock: socket.socket, key: bytes):
        self._sock      = sock
        self._aesgcm    = AESGCM(key)
        self._send_lock = threading.Lock()

    # -------------------------------------------------------------- #
    # Handshake                                                       #
    # -------------------------------------------------------------- #

    @classmethod
    def server_handshake(cls, sock: socket.socket,
                         signing_key: Ed25519PrivateKey) -> "SecureChannel":
        """
        Servidor:
          1. Recebe chave efémera do cliente.
          2. Gera par efémero X25519.
          3. Assina a chave efémera com a chave Ed25519 de longa duração.
          4. Envia: signing_pub + eph_pub + assinatura (128 bytes).
          5. Deriva chave de sessão via HKDF.
        """
        client_pub_bytes = tcp.recv_raw(sock)
        if not client_pub_bytes or len(client_pub_bytes) != _X25519_PUB_SIZE:
            raise ConnectionError("Handshake falhou: chave pública do cliente inválida.")

        eph_priv      = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signing_pub_bytes = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signature = signing_key.sign(eph_pub_bytes)  # 64 bytes

        tcp.send_raw(sock, signing_pub_bytes + eph_pub_bytes + signature)

        client_pub    = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = eph_priv.exchange(client_pub)
        key = HKDF(algorithm=SHA256(), length=32, salt=None,
                   info=b"chat-session-key").derive(shared_secret)
        return cls(sock, key)

    @classmethod
    def client_handshake(cls, sock: socket.socket,
                         pinned_server_pub: bytes | None = None
                         ) -> tuple["SecureChannel", bytes]:
        """
        Cliente:
          1. Gera e envia chave efémera X25519.
          2. Recebe: signing_pub + eph_pub_server + assinatura (128 bytes).
          3. Verifica assinatura (MITM check).
          4. TOFU: verifica ou guarda a chave de assinatura.
          5. Deriva chave de sessão via HKDF.

        Devolve (SecureChannel, server_signing_pub_bytes).
        Lança ConnectionError se a verificação falhar.
        """
        eph_priv      = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        tcp.send_raw(sock, eph_pub_bytes)

        raw = tcp.recv_raw(sock)
        if not raw or len(raw) != _SERVER_HELLO_SIZE:
            raise ConnectionError(
                f"Handshake falhou: resposta do servidor inválida "
                f"(esperados {_SERVER_HELLO_SIZE} bytes, recebidos {len(raw) if raw else 0})."
            )

        server_signing_pub_bytes = raw[:_ED25519_PUB_SIZE]
        server_eph_pub_bytes     = raw[_ED25519_PUB_SIZE:_ED25519_PUB_SIZE + _X25519_PUB_SIZE]
        signature                = raw[_ED25519_PUB_SIZE + _X25519_PUB_SIZE:]

        # TOFU: verificar se a chave de assinatura corresponde à guardada
        if pinned_server_pub is not None and server_signing_pub_bytes != pinned_server_pub:
            raise ConnectionError(
                "ALERTA DE SEGURANÇA: a chave de longa duração do servidor mudou!\n"
                "Possível ataque Man-in-the-Middle. Ligação recusada."
            )

        # Verificar assinatura da chave efémera do servidor
        try:
            Ed25519PublicKey.from_public_bytes(server_signing_pub_bytes).verify(
                signature, server_eph_pub_bytes
            )
        except InvalidSignature:
            raise ConnectionError(
                "Handshake falhou: assinatura do servidor inválida. "
                "Possível ataque Man-in-the-Middle."
            )

        server_eph_pub = X25519PublicKey.from_public_bytes(server_eph_pub_bytes)
        shared_secret  = eph_priv.exchange(server_eph_pub)
        key = HKDF(algorithm=SHA256(), length=32, salt=None,
                   info=b"chat-session-key").derive(shared_secret)

        return cls(sock, key), server_signing_pub_bytes

    # -------------------------------------------------------------- #
    # Envio e recepção com AES-256-GCM                                #
    # -------------------------------------------------------------- #

    def send(self, data: bytes):
        """Thread-safe. Encripta e envia: [ nonce[12] ][ ciphertext + tag GCM ]"""
        nonce      = os.urandom(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        with self._send_lock:
            tcp.send_raw(self._sock, nonce + ciphertext)

    def recv(self) -> bytes | None:
        """Devolve None se a ligação fechou. Lança ValueError se a tag GCM falhar."""
        raw = tcp.recv_raw(self._sock)
        if raw is None:
            return None
        if len(raw) < NONCE_SIZE:
            raise ValueError("Mensagem demasiado curta para conter nonce.")
        return self._aesgcm.decrypt(raw[:NONCE_SIZE], raw[NONCE_SIZE:], None)

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass
