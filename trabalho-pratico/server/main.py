import configparser
from state import ServerState
from server import ChatServer

def main():
    # 1. Load Configurations
    config = configparser.ConfigParser()
    config.read('../config.ini')
    host = config['SERVER']['address']
    port = config['SERVER'].getint('port')

    # 2. Initialize Seerver State (Business Logic)
    state = ServerState()

    # 3. Initialize and Start the Server's socket and accept loop (Network-side)
    server = ChatServer(host, port, state)
    server.start()

if __name__ == "__main__":
    main()