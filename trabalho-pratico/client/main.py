import configparser
import transport as tcp
from controller import ClientController
import interface as ui

def main():
    config = configparser.ConfigParser()
    config.read('../config.ini')
    
    host = config['SERVER']['address']
    port = config['SERVER'].getint('port')

    # Inicialização dos recursos
    sock = tcp.connect(host, port)
    if sock is None:
        return
    controller = ClientController(sock)

    try:
        # Passa o controlo total para a UI
        ui.start(controller)
    except KeyboardInterrupt:
        pass
    finally:
        # Garante que o socket fecha independentemente de como a UI terminou
        controller.disconnect()
        ui.clear()
        print("Até logo.\n")

if __name__ == "__main__":
    main()