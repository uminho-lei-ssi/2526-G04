# Projeto

Aplicação de chat com End-to-End Encryption (E2EE), desenvolvida em Python.

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

**1. Iniciar o servidor**

```bash
cd server
python3 main.py
```

**2. Ligar um cliente**

```bash
cd client
python3 main.py
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