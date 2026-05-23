import json
import socket
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common.secureChannel import SecureChannel
from server.state import ServerState
from server import ca

class ClientSession(threading.Thread):
    def __init__(self, ch: SecureChannel, addr, state: ServerState,
                 signing_key: Ed25519PrivateKey):
        super().__init__(daemon=True)
        self.ch, self.addr, self.state = ch, addr, state
        self.signing_key = signing_key
        self.username = None

    def run(self):
        try:
            while True:
                data = self.ch.recv()
                if not data:
                    break
                if self._dispatch(data) is False:
                    break
        finally:
            self._cleanup()

    def _dispatch(self, raw: bytes):
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_response(False, "ERRO mensagem invalida.")
            return

        if not isinstance(message, dict):
            self._send_response(False, "ERRO formato de mensagem invalido.")
            return

        handlers = {
            "REGISTER":       self._handle_register,
            "LOGIN":          self._handle_login,
            "LOGOUT":         self._handle_logout,
            "GET_CONTACTS":   self._handle_get_contacts,
            "GET_PUB_KEY":    self._handle_get_pub_key,
            "ADD_CONTACT":    self._handle_add_contact,
            "REMOVE_CONTACT": self._handle_remove_contact,
            "SEND_MESSAGE":   self._handle_send_message,
            "FETCH_MESSAGES": self._handle_fetch_messages,
        }

        cmd = str(message.get("type", "")).strip().upper()
        handler = handlers.get(cmd)
        if handler:
            try:
                return handler(message)
            except Exception as e:
                self._send_response(False, f"ERRO ao processar comando {cmd}: {e}")
                return
        else:
            self._send_response(False, f"ERRO comando desconhecido: {cmd}")

    def _handle_register(self, payload: dict):
        user     = str(payload.get("username", "")).strip()  # hash do cliente
        pwd      = str(payload.get("password", ""))
        pub_key  = str(payload.get("pub_key",  "")).strip()
        blob     = str(payload.get("blob", "")).strip()

        if not user or not pwd:
            return self._send_response(False, "ERRO username/password obrigatorios.")
        if not pub_key or not blob:
            return self._send_response(False, "ERRO chaves criptograficas obrigatorias.")

        cert_json, sig_b64 = ca.issue_certificate(user, pub_key, self.signing_key)

        if not self.state.register_user(user, pwd, pub_key, blob, cert_json, sig_b64):
            return self._send_response(False, f"ERRO utilizador já existe.")

        print(f"  Registado: {user[:8]}...")
        self._send_response(True, f"OK registo efetuado.")

    def _handle_login(self, payload: dict):
        user = str(payload.get("username", "")).strip()
        pwd  = str(payload.get("password", ""))

        if not user or not pwd:
            return self._send_response(False, "ERRO username/password obrigatorios.")
        if self.username:
            return self._send_response(False, "ERRO ja autenticado.")
        if not self.state.authenticate_user(user, pwd):
            return self._send_response(False, "ERRO credenciais invalidas.")
        if not self.state.login_user(user, self):
            return self._send_response(False, "ERRO sessao ja ativa.")

        self.username = user
        print(f"  Login: {user[:8]}...")
        bundle = self.state.get_key_bundle(user) 
        self._send_response(True, f"OK autenticado.", bundle)

    def _handle_logout(self, message=None):
        if self.username:
            self.state.logout_user(self.username)
            self.username = None
        self._send_response(True, f"OK sessao terminada.")

    def _handle_get_contacts(self, message=None):
        if not self._ensure_authenticated():
            return
        contacts = self.state.get_contacts(self.username)
        contact_keys = self.state.pop_contact_keys(self.username)
        self._send_response(True, "OK lista de contactos.", {
            "contacts":    contacts,
            "contact_keys": contact_keys,
        })

    def _handle_get_pub_key(self, payload: dict):
        if not self._ensure_authenticated():
            return
        target = str(payload.get("uid", "")).strip()
        if not target:
            return self._send_response(False, "ERRO UID obrigatorio.")
        pub_key = self.state.get_pub_key(target)
        if not pub_key:
            return self._send_response(False, f"ERRO utilizador nao existe.")
        cert_pair = self.state.get_cert(target)
        if not cert_pair:
            return self._send_response(False, "ERRO certificado nao disponivel.")
        cert_json, sig_b64 = cert_pair
        self._send_response(True, "OK chave publica obtida.", {
            "pub_key": pub_key,
            "cert":    cert_json,
            "sig":     sig_b64,
        })

    def _handle_add_contact(self, payload: dict):
        if not self._ensure_authenticated():
            return
        contact             = str(payload.get("contact", "")).strip()
        enc_key_for_owner   = str(payload.get("enc_key_for_owner", "")).strip()
        enc_key_for_contact = str(payload.get("enc_key_for_contact", "")).strip()
        enc_username        = str(payload.get("enc_username", "")).strip()

        if not contact or not enc_key_for_owner or not enc_key_for_contact or not enc_username:
            return self._send_response(False, "ERRO dados de contacto incompletos.")

        ok, message = self.state.add_contact(self.username, contact)
        if not ok:
            return self._send_response(ok, message)
        
        # Adicionar reciprocamente no estado
        self.state.add_contact(contact, self.username)

        # Guardar chaves cifradas e o username opaco para handshake
        self.state.store_contact_key(self.username, contact, enc_key_for_owner, enc_key_for_contact, enc_username)

        self._send_response(True, message)

    def _handle_remove_contact(self, payload: dict):
        if not self._ensure_authenticated():
            return
        contact = str(payload.get("contact", "")).strip()
        if not contact:
            return self._send_response(False, "ERRO contacto obrigatorio.")
        ok, message = self.state.remove_contact(self.username, contact)
        self._send_response(ok, message)

    def _handle_send_message(self, payload: dict):
        if not self._ensure_authenticated():
            return
        recipient = str(payload.get("to", "")).strip()
        content   = str(payload.get("content", ""))
        if not recipient:
            return self._send_response(False, "ERRO destinatario obrigatorio.")
        if not content.strip():
            return self._send_response(False, "ERRO mensagem vazia.")
        contacts = self.state.get_contacts(self.username)
        if recipient not in contacts:
            return self._send_response(False, "ERRO destinatario fora da lista de contactos.")
        ok, message = self.state.queue_message(self.username, recipient, content)
        self._send_response(ok, message)

    def _handle_fetch_messages(self, payload: dict):
        if not self._ensure_authenticated():
            return
        contact_value = payload.get("contact")
        contact = contact_value.strip() if isinstance(contact_value, str) else None
        
        messages     = self.state.pop_messages(self.username, contact or None)
        contact_keys = self.state.pop_contact_keys(self.username)
        
        self._send_response(True, "OK sincronizacao concluida.", {
            "messages":     messages,
            "contact_keys": contact_keys,
        })

    def _ensure_authenticated(self) -> bool:
        if self.username:
            return True
        self._send_response(False, "ERRO autenticacao necessaria.")
        return False

    def _send_response(self, ok: bool, message: str, data: dict | None = None):
        payload = {"type": "RESPONSE", "ok": ok, "message": message}
        if data is not None:
            payload["data"] = data
        self.ch.send(json.dumps(payload).encode("utf-8"))

    def _cleanup(self):
        if self.username:
            self.state.logout_user(self.username)
            self.username = None
        self.ch.close()
        print(f"[-] {self.addr} desligou")


class ChatServer:
    def __init__(self, host, port, state, signing_key: Ed25519PrivateKey):
        self.addr        = (host, port)
        self.state       = state
        self.signing_key = signing_key
        self.sock        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self.sock.bind(self.addr)
        self.sock.listen()
        print(f"[*] Server listening on {self.addr}")
        try:
            while True:
                conn, addr = self.sock.accept()
                print(f"[+] Ligação de {addr} — a fazer handshake...")
                try:
                    ch = SecureChannel.server_handshake(conn, self.signing_key)
                    print(f"    Canal seguro autenticado com {addr}")
                except Exception as e:
                    print(f"    Handshake falhou com {addr}: {e}")
                    conn.close()
                    continue
                ClientSession(ch, addr, self.state, self.signing_key).start()
        except KeyboardInterrupt:
            self.sock.close()