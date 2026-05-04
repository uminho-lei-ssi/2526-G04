import configparser
from server.state import ServerState
from server.server import ChatServer

def main():
    # 1. Load Configurations
    config = configparser.ConfigParser()
    config.read('server/config.ini')
    host = config['SERVER']['address']
    port = config['SERVER'].getint('port')

    # 2. Initialize Server State
    state = ServerState()

    # 3. Initialize and Start the Server's accept loop (network)
    server = ChatServer(host, port, state)
    server.start()

if __name__ == "__main__":
    main()