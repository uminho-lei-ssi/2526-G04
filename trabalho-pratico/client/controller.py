import json

from common.secureChannel import SecureChannel
from client.storage.keystore import KeyStore
from client.storage.messageStore import MessageStore


class ClientController:
    def __init__(self, ch: SecureChannel, keystore: KeyStore, message_store: MessageStore):
        self._ch            = ch
        self._username:  str | None = None
        self._priv_key   = None  # X25519PrivateKey em memória após login
        self._keystore   = keystore
        self._msg_store  = message_store

    def register(self, username: str, password: str) -> tuple[bool, str]:
        try:
            pub_b64, enc_priv_b64 = self._keystore.generate_and_save(username, password)
        except Exception as e:
            return False, f"Erro ao gerar chaves: {e}"

        ok, message, _ = self._request({
            "type":     "REGISTER",
            "username": username,
            "password": password,
            "pub_key":  pub_b64,
            "enc_priv": enc_priv_b64,
        })

        if not ok:
            self._keystore.delete_local_keys(username)

        return ok, message

    def login(self, username: str, password: str) -> tuple[bool, str]:
        ok, message, data = self._request({
            "type":     "LOGIN",
            "username": username,
            "password": password,
        })

        if not ok:
            return ok, message

        pub_b64      = data.get("pub_key", "")
        enc_priv_b64 = data.get("enc_priv", "")

        try:
            self._keystore.save_from_server(username, pub_b64, enc_priv_b64)
            self._priv_key = self._keystore.load_private_key(username, password)
        except ValueError as e:
            return False, f"Erro ao carregar chaves: {e}"
        
        _, _, data = self._request({"type": "FETCH_MESSAGES"})
        contact_keys = data.get("contact_keys", {})
        self._process_contact_keys(contact_keys)

        self._username = username
        return ok, message

    def logout(self) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "LOGOUT"})
        if ok:
            if self._username:
                self._keystore.delete_local_keys(self._username)
            self._username = None
            self._priv_key = None
        return ok, message

    def get_contacts(self) -> list[str]:
        ok, _, data = self._request({"type": "GET_CONTACTS"})
        if not ok:
            return []
        return [c for c in data.get("contacts", []) if isinstance(c, str)]

    def add_contact(self, contact: str) -> tuple[bool, str]:
        # Verificar se já é contacto
        contacts = self.get_contacts()
        is_added = contact in contacts
        if is_added: return

        # Pedir chave pública do contacto ao servidor
        ok, _, data = self._request({"type": "GET_PUB_KEY", "username": contact})
        if not ok:
            return False, f"Não foi possível obter a chave pública de '{contact}'."

        contact_pub_b64 = data.get("pub_key", "")
        if not contact_pub_b64:
            return False, f"Servidor não devolveu chave pública de '{contact}'."

        # Gerar chave simétrica, guardar para o owner e obter blob cifrado para o contact
        try:
            enc_for_contact, enc_for_self = self._keystore.generate_contact_key(
                self._username, contact, contact_pub_b64, self._priv_key
            )
        except Exception as e:
            return False, f"Erro ao gerar chave de contacto: {e}"

        # Pedir ao server para registar contacto e enviar depois a chave cifrada para o contacto
        ok, message, _ = self._request({
            "type":                "ADD_CONTACT",
            "contact":             contact,
            "enc_key_for_owner":   enc_for_self,
            "enc_key_for_contact": enc_for_contact,
        })

        return ok, message

    def remove_contact(self, contact: str) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "REMOVE_CONTACT", "contact": contact})
        return ok, message

    def send_message(self, recipient: str, content: str) -> tuple[bool, str]:
        sym_key = self._keystore.get_contact_key(self._username, recipient, self._priv_key)
        if not sym_key:
            return False, f"Sem chave de sessão para '{recipient}'. Abra a conversa primeiro."
 
        # Cifrar no cliente — servidor recebe apenas ciphertext
        e2ee_payload = self._msg_store.encrypt_message(content, sym_key)
 
        ok, message, _ = self._request({
            "type":    "SEND_MESSAGE",
            "to":      recipient,
            "content": e2ee_payload,
        })
 
        if ok:
            # Guardar no historico local (cifrado)
            self._msg_store.append_ciphered(self._username, recipient,
                                   self._username, content, sym_key)
 
        return ok, message
    
    def fetch_messages(self, contact: str) -> list[dict]:
        """
        Vai buscar mensagens novas ao servidor para um determinado contacto, persiste-as localmente
        e devolve o histórico completo da conversa decifrado.
        Também processa chaves pendentes de novos contactos.
        """
        ok, _, data = self._request({"type": "FETCH_MESSAGES", "contact": contact})
 
        if ok:
            # Processar chaves pendentes de contactos que nos adicionaram
            contact_keys = data.get("contact_keys", {})
            self._process_contact_keys(contact_keys)
 
            # Persistir mensagens novas recebidas
            new_messages = data.get("messages", [])
            sym_key = self._keystore.get_contact_key(self._username, contact, self._priv_key)
            if sym_key:
                for m in new_messages:
                    if isinstance(m, dict):
                        # Decifrar E2EE antes de guardar no histórico local com novo nonce
                        plaintext = self._msg_store.decrypt_message(m.get("content", ""), sym_key)
                        if plaintext is not None:
                            self._msg_store.append_ciphered(
                                self._username, contact,
                                m.get("from", "?"), plaintext,
                                sym_key, ts=m.get("ts")
                            )
 
        # Devolver historico completo
        sym_key = self._keystore.get_contact_key(self._username, contact, self._priv_key)
        if not sym_key:
            return []
        return self._msg_store.load_all(self._username, contact, sym_key)
 
    def _process_contact_keys(self, contact_keys: dict[str, str]):
        """
        Decifra e guarda chaves simétricas enviadas por contactos que nos adicionaram.
        contact_keys = { sender: enc_key_blob_b64 }
        """
        for contact_name, blob in contact_keys.items():            
            try:
                if len(blob) == 124:
                    # Formato com chave efemera (ECDH)
                    self._keystore.receive_contact_key(
                        self._username, contact_name, blob, self._priv_key
                    )
                elif len(blob) == 80:
                    # Formato simples (AES direto do owner)
                    self._keystore.receive_owner_key(self._username, contact_name, blob, self._priv_key)
                else: print(f"Formato de chave de contacto inválido detetado.")
            except Exception as e:
                print(f"  Aviso: erro ao processar chave de '{contact_name}': {e}")

    def _request(self, payload: dict) -> tuple[bool, str, dict]:
        try:
            self._ch.send(json.dumps(payload).encode("utf-8"))
            resp = self._ch.recv()
        except OSError:
            return False, "Falha de comunicacao com o servidor.", {}

        if resp is None:
            return False, "Servidor desligou.", {}

        try:
            message = json.loads(resp.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "Resposta invalida do servidor.", {}

        if not isinstance(message, dict):
            return False, "Formato invalido de resposta.", {}

        ok   = bool(message.get("ok", False))
        text = str(message.get("message", "Sem mensagem."))
        data = message.get("data")
        if not isinstance(data, dict):
            data = {}
        return ok, text, data

    def disconnect(self):
        if self._username:
            self._keystore.delete_local_keys(self._username)
            self._username = None
            self._priv_key = None
        self._ch.close()