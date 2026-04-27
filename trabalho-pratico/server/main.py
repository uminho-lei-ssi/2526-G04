import configparser
from server.state import ServerState
from server.server import ChatServer

def main():
    # 1. Load Configurations
    config = configparser.ConfigParser()
    config.read('common/config.ini')
    host = config['SERVER']['address']
    port = config['SERVER'].getint('port')

    # 2. Initialize Seerver State (Business Logic)
    state = ServerState()

    # 3. Initialize and Start the Server's socket and accept loop (Network-side)
    server = ChatServer(host, port, state)
    server.start()

if __name__ == "__main__":
    main()