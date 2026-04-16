import threading


class ServerState:
    """Manages the server's persistent state: users, online clients, offline messages."""

    def __init__(self):
        # { username: { "password_hash": str } }
        self._users: dict[str, dict] = {}
        # { username: handler_thread }
        self._online: dict[str, "ClientHandler"] = {}
        # { username: [raw_bytes, ...] }
        self._offline: dict[str, list[bytes]] = {}
        self._lock = threading.Lock()

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user. Returns True if successful, False if user exists."""
        with self._lock:
            if username in self._users:
                return False
            self._users[username] = {"password": password}  # hash later
            self._offline[username] = []
            return True

    def authenticate_user(self, username: str, password: str) -> bool:
        """Check if credentials are valid."""
        with self._lock:
            user = self._users.get(username)
            return user is not None and user["password"] == password

    def login_user(self, username: str, handler) -> bool:
        """Log in user if not already online. Returns True if successful."""
        with self._lock:
            if username in self._online: # User online não pode ter mais que uma sessão
                print("User is already logged in.")
                return False
            self._online[username] = handler
            return True

    def logout_user(self, username: str):
        """Remove user from online list."""
        with self._lock:
            self._online.pop(username, None)

    def get_offline_messages(self, username: str) -> list[bytes]:
        """Get and clear offline messages for user."""
        with self._lock:
            messages = self._offline.get(username, [])
            self._offline[username] = []
            return messages

    def add_offline_message(self, username: str, message: bytes):
        """Add a message to user's offline queue."""
        with self._lock:
            if username in self._offline:
                self._offline[username].append(message)