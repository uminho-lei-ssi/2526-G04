import configparser
import os
import common.transport as tcp
from common.secureChannel import SecureChannel
from client.controller import ClientController
from client.keystore import KeyStore
import client.interface as ui


def main():
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    config.read(config_path)

    host = config['SERVER']['address']
    port = config['SERVER'].getint('port')

    keys_dir = config['KEYSTORE'].get('keys_dir', 'data/keys')
    if not os.path.isabs(keys_dir):
        project_root = os.path.dirname(os.path.dirname(__file__))
        keys_dir = os.path.join(project_root, keys_dir)

    sock = tcp.connect(host, port)
    if sock is None:
        print("Erro: não foi possível ligar ao servidor.")
        return

    try:
        ch = SecureChannel.client_handshake(sock)
    except Exception as e:
        print(f"Erro no handshake: {e}")
        sock.close()
        return

    controller = ClientController(ch, KeyStore(keys_dir))

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