import base64
import configparser
import os

import common.transport as tcp
from common.secureChannel import SecureChannel
from client.controller import ClientController
from client.storage.keystore import KeyStore
from client.storage.messageStore import MessageStore
import client.interface as ui


_PINNED_KEY_FILE = "client/data/server_pubkey.b64"


def _tofu_verify(server_pub_bytes: bytes, project_root: str) -> bool:
    """
    Trust-On-First-Use para a chave de assinatura Ed25519 do servidor.
    1ª ligação: guarda e informa. Seguintes: verifica que não mudou.
    Devolve True se OK, False se há discrepância (possível MITM).
    """
    pinned_path = os.path.join(project_root, _PINNED_KEY_FILE)
    pub_b64     = base64.b64encode(server_pub_bytes).decode()

    if not os.path.exists(pinned_path):
        os.makedirs(os.path.dirname(pinned_path), exist_ok=True)
        with open(pinned_path, "w") as f:
            f.write(pub_b64)
        print(f"\n  [TOFU] Chave do servidor guardada: {pub_b64}\n")
        return True

    with open(pinned_path) as f:
        pinned = f.read().strip()

    if pinned == pub_b64:
        return True

    print("\n  *** ALERTA DE SEGURANÇA ***")
    print("  A chave de longa duração do servidor mudou!")
    print(f"  Esperada: {pinned}")
    print(f"  Recebida: {pub_b64}")
    print("  Possível ataque Man-in-the-Middle. Ligação terminada.\n")
    return False


def main():
    config      = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), "config.ini")
    config.read(config_path)

    host = config["SERVER"]["address"]
    port = config["SERVER"].getint("port")

    project_root = os.path.dirname(os.path.dirname(__file__))

    keys_dir = config["KEYSTORE"].get("keys_dir", "client/data")
    if not os.path.isabs(keys_dir):
        keys_dir = os.path.join(project_root, keys_dir)

    messages_dir = config["KEYSTORE"].get("messages_dir", "client/data/messages")
    if not os.path.isabs(messages_dir):
        messages_dir = os.path.join(project_root, messages_dir)

    sock = tcp.connect(host, port)
    if sock is None:
        print("Erro: não foi possível ligar ao servidor.")
        return

    try:
        ch, server_pub_bytes = SecureChannel.client_handshake(sock)
    except ConnectionError as e:
        print(f"Erro no handshake: {e}")
        sock.close()
        return
    except Exception as e:
        print(f"Erro inesperado no handshake: {e}")
        sock.close()
        return

    if not _tofu_verify(server_pub_bytes, project_root):
        ch.close()
        return

    controller = ClientController(ch, KeyStore(keys_dir), MessageStore(messages_dir),
                                  server_pub_bytes)

    try:
        ui.start(controller)
    except KeyboardInterrupt:
        pass
    finally:
        controller.disconnect()
        ui.clear()
        print("Até logo.\n")


if __name__ == "__main__":
    main()
