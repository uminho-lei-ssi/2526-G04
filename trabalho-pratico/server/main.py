import base64
import configparser
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_pem_private_key,
)

from server.state import ServerState
from server.server import ChatServer


_SIGNING_KEY_PATH = "server/data/server_signing.pem"


def load_or_generate_signing_key() -> Ed25519PrivateKey:
    """
    Carrega a chave Ed25519 de longa duração do servidor, ou gera uma nova.
    A chave pública é impressa no arranque para o administrador copiar para os clientes (TOFU).
    """
    os.makedirs(os.path.dirname(_SIGNING_KEY_PATH), exist_ok=True)

    if os.path.exists(_SIGNING_KEY_PATH):
        with open(_SIGNING_KEY_PATH, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        print(f"[*] Chave de assinatura carregada. Pub: {pub_b64}")
        return key

    key = Ed25519PrivateKey.generate()
    with open(_SIGNING_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    print(f"[*] Nova chave de assinatura gerada. Pub: {pub_b64}")
    print(f"    Guardada em: {_SIGNING_KEY_PATH!r}")
    print(f"    (Clientes aceitam automaticamente na 1ª ligação — TOFU)")
    return key


def main():
    config = configparser.ConfigParser()
    config.read("server/config.ini")
    host = config["SERVER"]["address"]
    port = config["SERVER"].getint("port")

    signing_key = load_or_generate_signing_key()
    state       = ServerState()
    server      = ChatServer(host, port, state, signing_key)
    server.start()


if __name__ == "__main__":
    main()
