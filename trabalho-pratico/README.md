# Secure Chat — SSI 2025/26 · Grupo 04

Aplicação de chat segura cliente-servidor com E2EE, PKI integrada e mensagens offline.  
Implementada em Python com a biblioteca `cryptography`.

---

## Estado do Projecto

### Requisitos Base

| Requisito | Estado |
|-----------|--------|
| Registo e autenticação de utilizadores | ✅ Feito |
| Canal de transporte seguro (TCP + cifra) | ✅ Feito |
| Autenticação do servidor (Ed25519, TOFU) | ✅ Feito |
| E2EE nas mensagens (por par de contactos) | ✅ Feito |
| Gestão de contactos (adicionar/remover/listar) | ✅ Feito |
| Identidade opaca (SHA-256 do username) | ✅ Feito |
| Persistência do estado no servidor | ✅ Feito |

### Valorizações

| Valorização | Estado |
|-------------|--------|
| Mensagens Offline | ✅ Feito |
| PKI / Entidade de Certificação (CA self-signed) | ✅ Feito |
| Forward Secrecy | ❌ Por fazer |
| Modo Descentralizado (PGP-like / P2P) | ❌ Por fazer |
| Mensagens de Grupo | ❌ Por fazer |

### TODOs pendentes (segurança / funcionalidade)

**Alta prioridade:**
- [ ] Limite de tentativas de login (mitigação de bruteforce)
- [ ] Requisitos mínimos de segurança na password
- [ ] Cleanup de credenciais locais ao receber SIGINT/KeyboardInterrupt
- [ ] `process_contact_keys` só ao aceitar explicitamente um contacto (evitar flood/DoS)
- [ ] Registo deixa credenciais em disco sem fazer login — limpar ou fazer login automático

**Média prioridade:**
- [ ] Paginação do histórico de mensagens (evitar UI inutilizável com histórico longo)

**Baixa prioridade (UX):**
- [ ] Sair de conversa leva ao menu de contactos
- [ ] Contactos com mensagens novas aparecem no topo
- [ ] Alterar password / apagar conta

---

## Arquitectura

```
.
├── client/
│   ├── main.py              # Ponto de entrada; handshake TLS + TOFU; inicia UI
│   ├── config.ini           # Configuração (endereço servidor, diretórios)
│   ├── controller.py        # Lógica de negócio (login, contactos, mensagens, PKI)
│   ├── interface.py         # UI interativa em terminal
│   └── storage/
│       ├── keystore.py      # Master Seed, X25519, chaves de contactos (AES-GCM)
│       └── messageStore.py  # Histórico local cifrado por conversa
├── server/
│   ├── main.py              # Ponto de entrada; gera/carrega chave Ed25519 da CA
│   ├── server.py            # Servidor TCP, despacho de comandos por sessão
│   ├── state.py             # Estado global (utilizadores, offline queue, contactos)
│   └── ca.py                # Emissão de certificados (CA)
├── common/
│   ├── secureChannel.py     # Canal seguro: X25519 + Ed25519 + AES-256-GCM
│   ├── transport.py         # Framing TCP (length-prefixed)
│   └── ca.py                # Verificação de certificados (lado cliente)
└── README.md
```

---

## Modelo de Segurança

### Canal de Transporte

Handshake autenticado ao estabelecer cada ligação TCP:

```
C → S : eph_pub_client  (32 bytes X25519)
S → C : signing_pub     (32 bytes Ed25519, chave de longa duração do servidor)
        + eph_pub_server (32 bytes X25519)
        + sig(signing_priv, eph_pub_server)  (64 bytes Ed25519)
```

O cliente verifica a assinatura e valida `signing_pub` via **TOFU** (guardada em `client/data/server_pubkey.b64` na primeira ligação). A chave de sessão é derivada por `HKDF-SHA256(X25519(eph_priv_c, eph_pub_s), info="chat-session-key")`. Todas as mensagens são cifradas com **AES-256-GCM**.

### PKI — Entidade de Certificação

O servidor age como CA self-signed. No **registo**, emite um certificado digital:

```json
{ "uid": "<sha256-hex do username>", "pub_key": "<base64 X25519>", "issued_at": <unix_ts> }
```

Assinado com Ed25519 (`signing_key` do servidor). Quando um cliente adiciona um contacto, recebe a `pub_key` acompanhada de `(cert_json, sig_b64)` e **verifica a assinatura** com a `signing_pub` já fixada via TOFU antes de usar a chave. Isto garante autenticidade mesmo que o servidor seja comprometido em trânsito.

### Identidade

O username nunca é enviado ao servidor em claro. É substituído pelo seu **SHA-256 em hex** (`uid`). O username real é trocado entre os dois clientes cifrado com a chave simétrica E2EE do par.

### E2EE por Par de Contactos

Quando Alice adiciona Bob:

1. Alice pede a `pub_key` de Bob ao servidor, verifica o certificado CA.
2. Alice gera uma chave simétrica AES-256 (`sym_key`) aleatória.
3. Cifra `sym_key` para Bob via **ECDH efémero** (X25519): `enc_for_contact = eph_pub ‖ nonce ‖ AES-GCM(HKDF(X25519(eph, bob_pub)), sym_key)`.
4. Cifra `sym_key` para si mesma com a sua *storage key* (derivada da Master Seed).
5. Envia ambos ao servidor; Bob recebe `enc_for_contact` na próxima sincronização e decifra com a sua chave privada X25519.

Todas as mensagens e metadados trocados são cifrados com `sym_key` (AES-256-GCM).

### Passwords e Chaves Locais

- Passwords: **PBKDF2-HMAC-SHA256**, 150 000 iterações, salt de 16 bytes (armazenadas no servidor).
- Master Seed (32 bytes aleatórios): cifrada com **AES-256-GCM** cuja chave é derivada da password via PBKDF2. Blob `salt ‖ nonce ‖ enc_seed` sincronizado com o servidor.
- Chave de identidade X25519: derivada da Master Seed via `HKDF(seed, info="identity-key")`.
- *Storage key* (para chaves de contactos em repouso): `HKDF(seed, info="contact-key-storage")`.

---

## Como Executar

### Setup

```bash
cd trabalho-pratico
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

### Servidor

```bash
python3 -m server.main
```

Gera (ou carrega) a chave Ed25519 da CA em `server/data/server_signing.pem` e imprime a chave pública. Escuta na porta configurada em `server/config.ini` (padrão: `12345`).

### Cliente

```bash
python3 -m client.main
```

Na primeira ligação, aceita a chave do servidor via TOFU e guarda-a em `client/data/server_pubkey.b64`. Múltiplos clientes podem correr em simultâneo.

### Reset de estado

```bash
./resetState.sh
```

---

## Protocolo de Aplicação (JSON sobre AES-256-GCM/TCP)

Todos os comandos são JSON sobre o canal cifrado. O servidor responde sempre com:

```json
{ "type": "RESPONSE", "ok": true|false, "message": "...", "data": { ... } }
```

| Comando | Campos obrigatórios | Notas |
|---------|---------------------|-------|
| `REGISTER` | `username` (uid), `password`, `pub_key`, `blob` | Servidor emite certificado CA |
| `LOGIN` | `username` (uid), `password` | Devolve `pub_key` + `blob` para sincronizar cofre |
| `LOGOUT` | — | |
| `GET_PUB_KEY` | `uid` | Devolve `pub_key`, `cert`, `sig` |
| `GET_CONTACTS` | — | Devolve lista de UIDs + `contact_keys` pendentes |
| `ADD_CONTACT` | `contact` (uid), `enc_key_for_owner`, `enc_key_for_contact`, `enc_username` | |
| `REMOVE_CONTACT` | `contact` (uid) | |
| `SEND_MESSAGE` | `to` (uid), `content` (E2EE blob) | |
| `FETCH_MESSAGES` | `contact` (uid, opcional) | Devolve mensagens + `contact_keys` pendentes |

---

## Dependências

- Python 3.10+
- `cryptography` — X25519, Ed25519, AES-256-GCM, PBKDF2-HMAC, HKDF
