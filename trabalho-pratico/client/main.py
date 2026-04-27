import configparser
import common.transport as tcp
from common.security import SecureChannel
from client.controller import ClientController
import client.interface as ui


def main():
    config = configparser.ConfigParser()
    config.read('common/config.ini')

    host = config['SERVER']['address']
    port = config['SERVER'].getint('port')

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

    controller = ClientController(ch)

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