import json
import os

from common.secureChannel import SecureChannel
from common.ca import verify_certificate
from client.storage.keystore import KeyStore
from client.storage.messageStore import MessageStore


class ClientController:
    def __init__(self, ch: SecureChannel, keystore: KeyStore,
                 message_store: MessageStore, server_signing_pub: bytes):
        self._ch                 = ch
        self._username:  str | None = None
        self._keystore   = keystore
        self._msg_store  = message_store
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
            seed = self._keystore.load_master_seed(username, password)
            # regista seed no keystore para uso por outros métodos
            self._keystore.set_active_user(username, seed)
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
            # limpar seed activo e ficheiros locais via KeyStore
            self._keystore.clear_active_user()
            self._username    = None
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
                self._username, uid, contact_pub_b64
            )
        except Exception as e:
            return False, f"Erro ao gerar chave de contacto: {e}"

        # Cifrar o nosso username para o contacto o conhecer
        sym_key      = self._keystore.get_contact_key(self._username, uid)
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
        sym_key = self._keystore.get_contact_key(self._username, uid)
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

            sym_key = self._keystore.get_contact_key(self._username, uid)
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

        sym_key = self._keystore.get_contact_key(self._username, uid)
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
                        self._username, contact_uid, blob
                    )
                    # registar username de quem adicionou
                    enc_username = entry.get("enc_username", "")
                    if enc_username:
                        sym_key = self._keystore.get_contact_key(
                            self._username, contact_uid
                        )
                        if sym_key:
                            username_claro = self._msg_store.decrypt_message(enc_username, sym_key)
                            if username_claro:
                                self._keystore.save_contact_username(
                                    self._username, contact_uid, username_claro
                                )
                elif key_type == "owner":
                    self._keystore.receive_owner_key(
                        self._username, contact_uid, blob
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

    # ------------------------------------------------------------------ #
    # Grupos                                                             #
    # ------------------------------------------------------------------ #

    def _get_certified_pub_key(self, uid: str) -> tuple[str | None, str]:
        """Devolve (pub_key_b64, erro). Verifica certificado CA."""
        ok, _, data = self._request({"type": "GET_PUB_KEY", "uid": uid})
        if not ok:
            return None, f"Utilizador '{uid[:8]}...' não encontrado."
        cert_json = data.get("cert", "")
        sig_b64   = data.get("sig", "")
        if not cert_json or not sig_b64:
            return None, "Servidor não devolveu certificado."
        try:
            cert = verify_certificate(cert_json, sig_b64, self._server_signing_pub)
        except ValueError as e:
            return None, f"Certificado inválido: {e}"
        if cert.get("uid") != uid:
            return None, "Certificado não corresponde ao UID."
        return cert.get("pub_key", ""), ""

    def create_group(self, name: str, members: list[str]) -> tuple[bool, str]:
        """
        name: nome do grupo visível.
        members: lista de usernames dos membros (sem incluir o próprio).
        """
        self_uid = self._keystore.username_to_uid(self._username)

        # Resolver UIDs e verificar certificados de todos os membros
        all_uids_and_pubs: dict[str, str] = {}
        for m in members:
            uid = self._keystore.resolve_username_to_uid(self._username, m) or m
            if uid == self_uid:
                continue
            pub_b64, err = self._get_certified_pub_key(uid)
            if not pub_b64:
                return False, err
            all_uids_and_pubs[uid] = pub_b64

        if not all_uids_and_pubs:
            return False, "Sem membros válidos para criar o grupo."

        # Incluir o próprio utilizador com a sua pub_key local
        self_pub_b64 = self._keystore.load_public_key_bytes(self._username)
        import base64 as _b64
        all_uids_and_pubs[self_uid] = _b64.b64encode(self_pub_b64).decode()

        # Gerar chave de grupo e cifrar para cada membro via ECDH
        group_key = os.urandom(32)
        enc_keys  = {
            uid: self._keystore.encrypt_group_key_for(group_key, pub)
            for uid, pub in all_uids_and_pubs.items()
        }

        ok, message, data = self._request({
            "type":     "CREATE_GROUP",
            "name":     name,
            "members":  list(all_uids_and_pubs.keys()),
            "enc_keys": enc_keys,
        })

        if ok:
            group_id = data.get("group_id", "")
            if group_id:
                self._keystore.save_group_key(self._username, group_id, group_key, name)

        return ok, message

    def get_groups(self) -> list[dict]:
        """Devolve grupos do utilizador, sincronizando chaves em falta."""
        ok, _, data = self._request({"type": "GET_GROUPS"})
        if not ok:
            return []
        groups = data.get("groups", [])
        for g in groups:
            gid  = g.get("group_id", "")
            name = g.get("name", "")
            if gid and not self._keystore.get_group_key(self._username, gid):
                ok2, _, kdata = self._request({"type": "GET_GROUP_KEY", "group_id": gid})
                if ok2:
                    enc_key = kdata.get("enc_key", "")
                    if enc_key:
                        try:
                            self._keystore.receive_group_key(self._username, gid, enc_key, name)
                        except Exception as e:
                            print(f"  Aviso: não foi possível decifrar chave do grupo '{name}': {e}")
        return groups

    def send_group_message(self, group_id: str, content: str) -> tuple[bool, str]:
        group_key = self._keystore.get_group_key(self._username, group_id)
        if not group_key:
            return False, "Sem chave para este grupo."
        e2ee = self._msg_store.encrypt_message(content, group_key)
        ok, message, _ = self._request({
            "type":     "SEND_GROUP_MESSAGE",
            "group_id": group_id,
            "content":  e2ee,
        })
        if ok:
            self._msg_store.append_ciphered(
                self._username, f"grp_{group_id}",
                self._username, content, group_key
            )
        return ok, message

    def fetch_group_messages(self, group_id: str) -> list[dict]:
        group_key = self._keystore.get_group_key(self._username, group_id)
        if not group_key:
            return []
        ok, _, data = self._request({"type": "FETCH_GROUP_MESSAGES", "group_id": group_id})
        if ok:
            for m in data.get("messages", []):
                if not isinstance(m, dict):
                    continue
                plaintext = self._msg_store.decrypt_message(m.get("content", ""), group_key)
                if plaintext is not None:
                    sender_uid = m.get("from", "?")
                    sender = self._keystore.resolve_uid(self._username, sender_uid) or sender_uid
                    self._msg_store.append_ciphered(
                        self._username, f"grp_{group_id}",
                        sender, plaintext, group_key, ts=m.get("ts")
                    )
        return self._msg_store.load_all(self._username, f"grp_{group_id}", group_key)

    def add_group_member(self, group_id: str, member: str) -> tuple[bool, str]:
        group_key = self._keystore.get_group_key(self._username, group_id)
        if not group_key:
            return False, "Sem chave para este grupo."
        uid = self._keystore.resolve_username_to_uid(self._username, member) or member
        pub_b64, err = self._get_certified_pub_key(uid)
        if not pub_b64:
            return False, err
        enc_key = self._keystore.encrypt_group_key_for(group_key, pub_b64)
        ok, message, _ = self._request({
            "type":     "ADD_GROUP_MEMBER",
            "group_id": group_id,
            "uid":      uid,
            "enc_key":  enc_key,
        })
        return ok, message

    def remove_group_member(self, group_id: str, member: str) -> tuple[bool, str]:
        uid = self._keystore.resolve_username_to_uid(self._username, member) or member
        ok, message, _ = self._request({
            "type":     "REMOVE_GROUP_MEMBER",
            "group_id": group_id,
            "uid":      uid,
        })
        return ok, message

    def disconnect(self):
        # Limpeza centralizada em KeyStore: apaga ficheiros locais e limpa seed ativo
        self._keystore.clear_active_user()
        self._username    = None
        self._ch.close()