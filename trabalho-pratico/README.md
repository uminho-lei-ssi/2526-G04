# Projeto

Aplicação de chat com End-to-End Encryption (E2EE), desenvolvida em Python.

NOTA: security.py está fora de diretoria, fica por se transferir para uma diretoria common com config.ini.

---

## Estrutura do projeto

```
.
├── server.py
├── client.py
└── README.md
```

---

## Como executar

python3 -m venv .venv
source .venv/bin/activate

**1. Iniciar o servidor**

```bash
python3 -m server.main
```

**2. Ligar um cliente**

```bash
python3 -m client.main
```

Podem ser abertos múltiplos clientes em simultâneo.

---

## Protocolo de transporte

Toda a comunicação usa TCP com um esquema simples de framing binário:

```
[ 4 bytes (big-endian) ] [ N bytes de payload ]
   tamanho do payload       dados em UTF-8
```

---

## Roadmap

- [x] Comunicação cliente-servidor
- [ ] Mensagens estruturadas (tipo + campos)
- [ ] Registo e autenticação de utilizadores
- [ ] Gestão de contactos e sessões
- [ ] End-to-End Encryption (E2EE)
- [ ] Mensagens offline
- [ ] PKI / Autoridade de Certificação