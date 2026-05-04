# Secure Chat

Aplicação de chat segura cliente-servidor com registo, autenticação, gestão de contactos e mensagens offline.

NOTA: Handshake X25519 com derivação HKDF; após handshake, mensagens em plaintext por agora.

---

## Estrutura do projeto

```
.
├── client/
│   ├── main.py              # Ponto de entrada do cliente
│   ├── config.ini           # Configuração (servidor, keys_dir)
│   ├── controller.py        # Lógica de negócio (login, mensagens, contactos)
│   ├── interface.py         # UI interativa (terminal)
│   ├── keystore.py          # Gestão de chaves Ed25519 cifradas
│   └── transport.py         # Transporte TCP com framing
├── server/
│   ├── main.py              # Ponto de entrada do servidor
│   ├── server.py            # Servidor TCP e ClientSession
│   ├── state.py             # Estado global (utilizadores, mensagens offline)
│   └── transport.py         # Transporte TCP com framing
├── common/
│   ├── security.py          # SecureChannel com handshake X25519 + AES-GCM
│   └── transport.py         # Primitivas TCP (send/recv framing)
└── README.md
```

---

## Funcionalidades

### Autenticação e Utilizadores
- **Registo**: Criar nova conta com username e password
- **Login**: Autenticar com credenciais; password verificada com PBKDF2-SHA256
- **Logout**: Encerrar sessão

### Gestão de Contactos
- Adicionar/remover contactos da lista pessoal
- Listar contactos ordenados por nome

### Mensagens
- Enviar mensagens para contactos na lista
- Receber mensagens (online ou offline)
- Mensagens offline armazenadas e cifradas no servidor com AES-GCM

### Segurança
- **Handshake X25519**: Estabelecimento de canal seguro com ECDH
- **Derivação de chave**: HKDF-SHA256 com label "chat-session-key"
- **Transporte**: Mensagens em plaintext após handshake (sem cifra de aplicação)
- **Passwords**: PBKDF2-HMAC-SHA256 com 150k iterações, salt aleatório
- **Chaves locais**: Pares Ed25519 cifrados com AES-256-GCM (derivado da password)

---

## Como executar

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

Inicia servidor na porta 12345 (configurável em `common/config.ini`).

### Cliente

Em outro terminal:

```bash
python3 -m client.main
```

Múltiplos clientes podem rodar simultaneamente. Cada cliente armazena as suas chaves em `data/keys/<username>.json` (configurável em `client/config.ini`).

---

## Protocolo de Transporte

Toda a comunicação usa TCP com framing simples:

```
[ 4 bytes big-endian ] [ N bytes de payload ]
   tamanho do payload      dados em UTF-8
```

Após handshake X25519, as mensagens são trocadas em plaintext (sem cifra adicional) por agora.

---

## Protocolo de Aplicação

### Mensagens JSON

**Login**
```json
{"type": "LOGIN", "username": "alice", "password": "secret"}
```

**Registar**
```json
{"type": "REGISTER", "username": "bob", "password": "pass", 
 "pub_key": "<base64>", "enc_priv": "<base64>"}
```

**Enviar mensagem**
```json
{"type": "SEND_MESSAGE", "to": "alice", "content": "Oi!"}
```

**Obter mensagens**
```json
{"type": "FETCH_MESSAGES", "contact": "alice"}
```

### Resposta do servidor

```json
{"type": "RESPONSE", "ok": true/false, "message": "...", "data": {...}}
```

---

## Notas de Segurança

1. **Sem autenticação de servidor**: O handshake X25519 estabelece um canal privado mas não autentica o servidor (sem certificados).
2. **Mensagens não autenticadas**: Após handshake, mensagens não têm MAC ou assinatura digital.
3. **Armazenamento offline**: Mensagens offline cifradas no servidor com chave mestra (regenerável após reinício).
4. **Sem Perfect Forward Secrecy**: Reutiliza-se a mesma chave de sessão durante toda a sessão.

---

## Dependências

- `cryptography`: X25519, AESGCM, PBKDF2-HMAC, Ed25519
- Python 3.10+