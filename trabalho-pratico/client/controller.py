import json

from common.secureChannel import SecureChannel
from common.ca import verify_certificate
from client.storage.keystore import KeyStore
from client.storage.messageStore import MessageStore


class ClientController:
    def __init__(self, ch: SecureChannel, keystore: KeyStore,
                 message_store: MessageStore, server_signing_pub: bytes):
        self._ch                 = ch
        self._username:  str | None = None
        self._master_seed        = None
        self._keystore           = keystore
        self._msg_store          = message_store
        self._server_signing_pub = server_signing_pub

    def register(self, username: str, password: str) -> tuple[bool, str]:
        try:
            pub_b64, blob = self._keystore.generate_and_save(username, password)
        except Exception as e:
            return False, f"Erro ao gerar chaves: {e}"
        
        hash_username = self._keystore.username_to_uid(username)

        ok, message, _ = self._request({
            "type":     "REGISTER",
            "username": hash_username,
            "password": password,
            "pub_key":  pub_b64,
            "blob":     blob,
        })

        if not ok:
            self._keystore.delete_local_keys(username)

        return ok, message

    def login(self, username: str, password: str) -> tuple[bool, str]:
        hash_username = self._keystore.username_to_uid(username)
        ok, message, data = self._request({
            "type":     "LOGIN",
            "username": hash_username,
            "password": password,
        })

        if not ok:
            return ok, message

        try:
            self._keystore.save_from_server(username, data.get("pub_key", ""), data.get("blob", ""))
            self._master_seed = self._keystore.load_master_seed(username, password)
        except ValueError as e:
            return False, f"Erro ao carregar chaves: {e}"

        self._username = username

        # Processar chaves e usernames pendentes ao fazer login
        _, _, data = self._request({"type": "FETCH_MESSAGES"})
        self._process_contact_keys(data.get("contact_keys", {}))

        return ok, message

    def logout(self) -> tuple[bool, str]:
        ok, message, _ = self._request({"type": "LOGOUT"})
        if ok:
            if self._username:
                self._keystore.delete_local_keys(self._username)
            self._username    = None
            self._master_seed = None
        return ok, message

    def get_contacts(self) -> list[str]:
        """Devolve lista de usernames resolvidos."""
        ok, _, data = self._request({"type": "GET_CONTACTS"})
        if not ok:
            return []
        self._process_contact_keys(data.get("contact_keys", {}))
        uids = [c for c in data.get("contacts", []) if isinstance(c, str)]
        return [self._keystore.resolve_uid(self._username, u) or u for u in uids]

    def add_contact(self, contact: str) -> tuple[bool, str]:
        """
        Aceita o `contact` que o utilizador introduz (nome visível) ou um `uid`.
        Resolve para `uid` antes de contactar o servidor.
        """
        # Resolver para UID (ou calcular se for um nome novo)
        uid = self._keystore.resolve_username_to_uid(self._username, contact) or contact

        # Prevenir adicionar a si mesmo
        if uid == self._keystore.username_to_uid(self._username):
            return False, "Não pode adicionar-se a si mesmo."

        ok, _, data = self._request({"type": "GET_PUB_KEY", "uid": uid})
        if not ok:
            return False, f"UID '{contact}' não encontrado."

        cert_json = data.get("cert", "")
        sig_b64   = data.get("sig", "")
        if not cert_json or not sig_b64:
            return False, "Servidor não devolveu certificado do contacto."

        try:
            cert = verify_certificate(cert_json, sig_b64, self._server_signing_pub)
        except ValueError as e:
            return False, f"Certificado inválido: {e}"

        contact_pub_b64 = cert.get("pub_key", "")
        if cert.get("uid") != uid or not contact_pub_b64:
            return False, "Certificado não corresponde ao UID solicitado."

        try:
            enc_for_contact, enc_for_self = self._keystore.generate_contact_key(
                self._username, uid, contact_pub_b64, self._master_seed
            )
        except Exception as e:
            return False, f"Erro ao gerar chave de contacto: {e}"

        # Cifrar o nosso username para o contacto o conhecer
        sym_key      = self._keystore.get_contact_key(self._username, uid, self._master_seed)
        enc_username = self._msg_store.encrypt_message(self._username, sym_key)

        ok, message, _ = self._request({
            "type":                "ADD_CONTACT",
            "contact":             uid,
            "enc_key_for_owner":   enc_for_self,
            "enc_key_for_contact": enc_for_contact,
            "enc_username":        enc_username,
        })

        if ok:
            # owner conhece username, guarda logo
            self._keystore.save_contact_username(self._username, uid, contact)

        return ok, message

    def remove_contact(self, contact: str) -> tuple[bool, str]:
        uid = self._keystore.resolve_username_to_uid(self._username, contact) or contact
        ok, message, _ = self._request({"type": "REMOVE_CONTACT", "contact": uid})
        return ok, message

    def send_message(self, recipient: str, content: str) -> tuple[bool, str]:
        uid     = self._keystore.resolve_username_to_uid(self._username, recipient) or recipient
        sym_key = self._keystore.get_contact_key(self._username, uid, self._master_seed)
        if not sym_key:
            return False, f"Sem chave de sessão para '{recipient}'."

        e2ee_payload = self._msg_store.encrypt_message(content, sym_key)

        ok, message, _ = self._request({
            "type":    "SEND_MESSAGE",
            "to":      uid,
            "content": e2ee_payload,
        })

        if ok:
            self._msg_store.append_ciphered(self._username, recipient,
                                            self._username, content, sym_key)
        return ok, message

    def fetch_messages(self, contact: str) -> list[dict]:
        uid = self._keystore.resolve_username_to_uid(self._username, contact) or contact

        ok, _, data = self._request({"type": "FETCH_MESSAGES", "contact": uid})

        if ok:
            self._process_contact_keys(data.get("contact_keys", {}))

            sym_key = self._keystore.get_contact_key(self._username, uid, self._master_seed)
            if sym_key:
                for m in data.get("messages", []):
                    if not isinstance(m, dict):
                        continue
                    plaintext = self._msg_store.decrypt_message(m.get("content", ""), sym_key)
                    if plaintext is not None:
                        sender_uid = m.get("from", uid)
                        sender     = self._keystore.resolve_uid(self._username, sender_uid) or sender_uid
                        self._msg_store.append_ciphered(
                            self._username, contact,
                            sender, plaintext,
                            sym_key, ts=m.get("ts")
                        )

        sym_key = self._keystore.get_contact_key(self._username, uid, self._master_seed)
        if not sym_key:
            return []
        return self._msg_store.load_all(self._username, contact, sym_key)

    def _process_contact_keys(self, contact_keys: dict[str, dict]):
        """
        Processa contact_keys recebidas do servidor.
        Cada entrada: { "type": "ecdh"|"owner", "key": b64, "enc_username": b64 }
        """
        for contact_uid, entry in contact_keys.items():
            if not isinstance(entry, dict):
                continue
            try:
                key_type = entry.get("type", "ecdh")
                blob     = entry.get("key", "")

                if key_type == "ecdh":
                    self._keystore.receive_contact_key(
                        self._username, contact_uid, blob, self._master_seed
                    )
                    # registar username de quem adicionou
                    enc_username = entry.get("enc_username", "")
                    if enc_username:
                        sym_key = self._keystore.get_contact_key(
                            self._username, contact_uid, self._master_seed
                        )
                        if sym_key:
                            username_claro = self._msg_store.decrypt_message(enc_username, sym_key)
                            if username_claro:
                                self._keystore.save_contact_username(
                                    self._username, contact_uid, username_claro
                                )
                elif key_type == "owner":
                    self._keystore.receive_owner_key(
                        self._username, contact_uid, blob, self._master_seed
                    )

            except Exception as e:
                print(f"  Aviso: erro ao processar chave de '{contact_uid}': {e}")

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
        self._username    = None
        self._master_seed = None
        self._ch.close()