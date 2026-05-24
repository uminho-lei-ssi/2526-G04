# Relatório — Projeto de Segurança de Sistemas Informáticos
**Grupo 04 · 2025/2026**

---

## 1. Descrição Geral

O projeto consiste numa aplicação de chat segura cliente-servidor implementada em Python com a biblioteca `cryptography`. O sistema garante *End-to-End Encryption* (E2EE) nas mensagens trocadas entre utilizadores, assegurando que o servidor — mesmo que comprometido — não consegue aceder ao conteúdo das comunicações nem identificar os participantes por nome. Para além da funcionalidade base, foram implementadas as valorizações de mensagens offline, PKI/CA e mensagens de grupo.

---

## 2. Arquitetura do Sistema

### 2.1 Visão Geral

O sistema segue um modelo cliente-servidor clássico com separação lógica estrita entre as três camadas:

```
┌─────────────────────────────────────────────────────┐
│  client/                                            │
│  ├── main.py          Ponto de entrada + TOFU       │
│  ├── controller.py    Lógica de negócio + E2EE      │
│  ├── interface.py     UI interativa em terminal     │
│  └── storage/                                       │
│      ├── keystore.py  Master Seed, chaves locais    │
│      └── messageStore.py  Histórico cifrado         │
├─────────────────────────────────────────────────────┤
│  server/                                            │
│  ├── main.py          Ponto de entrada + chave CA   │
│  ├── server.py        Dispatcher TCP por sessão     │
│  ├── state.py         Estado global + persistência  │
│  └── ca.py            Emissão de certificados       │
├─────────────────────────────────────────────────────┤
│  common/                                            │
│  ├── secureChannel.py  Canal seguro X25519+AES-GCM  │
│  ├── transport.py      Framing TCP length-prefixed  │
│  └── ca.py             Verificação de certificados  │
└─────────────────────────────────────────────────────┘
```

### 2.2 Servidor

O servidor corre em modo contínuo, aguardando ligações TCP. Cada ligação é tratada numa thread independente (`ClientSession`), que despacha comandos JSON recebidos através do canal seguro. O estado global (utilizadores, mensagens offline, contactos, grupos) é mantido em memória e persistido num ficheiro JSON (`server/data/server_state.json`). O servidor atua também como Autoridade de Certificação (CA), mantendo um par de chaves Ed25519 de longa duração (`server/data/server_signing.pem`).

### 2.3 Cliente

Cada instância do cliente corresponde a um utilizador. Após estabelecer o canal seguro com o servidor (handshake), o utilizador interage com uma interface de texto interativa. Toda a lógica criptográfica reside no `controller.py` e no `keystore.py`; a interface (`interface.py`) é agnóstica relativamente à segurança.

### 2.4 Protocolo de Transporte

A comunicação TCP usa *length-prefixed framing*: cada mensagem é precedida de 4 bytes big-endian com o comprimento do payload. O transporte implementa uma verificação de tamanho máximo (64 KB) para mitigar ataques de alocação de memória. Todo o payload após o handshake é cifrado com AES-256-GCM.

---

## 3. Fluxos de Comunicação

### 3.1 Handshake e Estabelecimento do Canal Seguro

O handshake é executado em cada nova ligação TCP e autentica o servidor perante o cliente através de chaves estáticas:

```
Cliente                                    Servidor
  │                                            │
  │──── eph_pub_client (32 B, X25519) ────────▶│
  │                                            │  gera eph_priv_server
  │                                            │  sig = Ed25519Sign(signing_priv, eph_pub_server)
  │◀─── signing_pub (32 B) ───────────────────│
  │◀─── eph_pub_server (32 B, X25519) ────────│
  │◀─── sig (64 B, Ed25519) ──────────────────│
  │                                            │
  │  verifica sig com signing_pub              │
  │  verifica TOFU (signing_pub guardada)      │
  │                                            │
  shared = X25519(eph_priv_client, eph_pub_server)
  session_key = HKDF-SHA256(shared, info="chat-session-key")
```

O cliente verifica a assinatura Ed25519 do servidor sobre a sua chave X25519. Na primeira ligação, a `signing_pub` é aceite e guardada (*Trust On First Use*); nas ligações seguintes, é comparada com a versão guardada — qualquer divergência é tratada como possível ataque MITM e a ligação é terminada.

A chave de sessão `session_key` é derivada via HKDF-SHA256 sobre o segredo partilhado X25519 estático e usada para cifrar todas as mensagens subsequentes com AES-256-GCM (nonce aleatório de 12 bytes por mensagem).

### 3.2 Registo

```
Cliente                                    Servidor
  │  gera Master Seed (32 B aleatórios)       │
  │  priv_X25519 = HKDF(seed, "identity-key") │
  │  pub_X25519 = priv_X25519.public_key()    │
  │  enc_seed = AES-GCM(PBKDF2(pwd), seed)   │
  │  blob = salt‖nonce‖enc_seed               │
  │  uid = SHA-256(username)                  │
  │                                            │
  │──── REGISTER {uid, hash_pwd, pub_key, blob} ──▶│
  │                                            │  cert = {uid, pub_key, issued_at}
  │                                            │  sig  = Ed25519Sign(signing_key, cert)
  │                                            │  guarda {hash(hash_pwd), pub_key, blob, cert, sig}
  │◀─── RESPONSE {ok: true} ──────────────────│
```

O servidor nunca vê o username em claro — recebe apenas o seu SHA-256. O blob cifrado (Master Seed protegida pela password) é guardado no servidor para permitir sincronização entre dispositivos.

### 3.3 Login

```
Cliente                                    Servidor
  │──── LOGIN {uid, hash_pwd} ────────────────────▶│
  │                                            │  verifica PBKDF2(hash_pwd) == hash_guardado
  │◀─── RESPONSE {ok, pub_key, blob} ─────────│
  │                                            │
  │  decifra blob com PBKDF2(pwd) → seed      │
  │  guarda seed em memória                   │
  │──── FETCH_MESSAGES {} ───────────────────▶│
  │◀─── {messages, contact_keys} ─────────────│
  │  processa contact_keys pendentes          │
```

Após login bem-sucedido, o cliente busca imediatamente as mensagens e chaves de contacto pendentes para completar eventuais handshakes E2EE iniciados por outros utilizadores enquanto estava offline.

### 3.4 Adição de Contacto e Troca de Chave E2EE

Este é o fluxo central de estabelecimento do canal E2EE entre dois utilizadores (Alice adiciona Bob):

```
Alice                     Servidor                      Bob
  │──── GET_PUB_KEY {uid_bob} ──────────────▶│
  │◀─── {pub_key_bob, cert_bob, sig_bob} ────│
  │  verifica cert_bob com signing_pub       │
  │  extrai pub_key_bob do certificado       │
  │                                           │
  │  sym_key = AES-256 aleatória (32 B)      │
  │  eph_priv = X25519.generate()            │
  │  shared = X25519(eph_priv, pub_bob)      │
  │  aes = HKDF(shared, "contact-key-exchange")
  │  enc_for_bob  = eph_pub‖nonce‖AES-GCM(aes, sym_key)
  │  enc_for_self = nonce‖AES-GCM(storage_key, sym_key)
  │  enc_username = AES-GCM(sym_key, "alice")
  │                                           │
  │──── ADD_CONTACT {uid_bob,                │
  │       enc_key_for_owner,                 │
  │       enc_key_for_contact,               │
  │       enc_username} ────────────────────▶│
  │                                           │  guarda enc_for_bob em contact_keys[bob]
  │◀─── RESPONSE {ok} ──────────────────────│
  │                                           │
  │             (Bob faz login)               │
  │             Bob──── FETCH_MESSAGES ─────▶│
  │             Bob◀─── {contact_keys: {alice: enc_for_bob}} ──│
  │             Bob decifra com priv_bob     │
  │             Bob guarda sym_key           │
  │             Bob decifra enc_username → "alice"
```

A chave simétrica `sym_key` é gerada aleatoriamente por Alice e cifrada via ECDH efémero para Bob, garantindo que apenas Bob (com a sua chave privada X25519) a pode decifrar. O servidor nunca vê `sym_key` em claro.

Após este handshake, todas as mensagens entre Alice e Bob são cifradas com `sym_key` usando AES-256-GCM antes de serem enviadas ao servidor.

### 3.5 Envio e Recepção de Mensagens

```
Alice                     Servidor                      Bob
  │  ciphertext = AES-GCM(sym_key, mensagem) │
  │──── SEND_MESSAGE {uid_bob, ciphertext} ─▶│
  │                                           │  guarda em offline[bob]
  │◀─── RESPONSE {ok} ──────────────────────│
  │                                           │
  │             Bob──── FETCH_MESSAGES ─────▶│
  │             Bob◀─── {messages: [{from, ciphertext, ts}]} │
  │             Bob: AES-GCM-Decrypt(sym_key, ciphertext)
```

O servidor armazena exclusivamente o ciphertext. Mesmo com acesso ao estado do servidor, um atacante vê apenas dados cifrados sem capacidade de os decifrar.

### 3.6 PKI — Emissão e Verificação de Certificados

No registo, o servidor emite um certificado digital associando o UID à chave pública X25519 do utilizador:

```json
{ "pub_key": "<base64 X25519>", "uid": "<sha256 hex>" }
```

O certificado é serializado em JSON canónico (chaves ordenadas, sem espaços) e assinado com a chave Ed25519 de longa duração do servidor. Esta assinatura é verificada pelo cliente sempre que obtém a chave pública de um contacto (fluxo `GET_PUB_KEY`), usando a `signing_pub` fixada via TOFU. Desta forma, mesmo que o servidor seja comprometido em memória, não pode substituir a chave pública de um utilizador sem invalidar a assinatura — a chave privada Ed25519 seria necessária para forjar um certificado válido.

### 3.7 Mensagens de Grupo

A criação de um grupo por Alice com membros Bob e Charlie:

```
Alice                                      Servidor
  │  GET_PUB_KEY(uid_bob)  → verifica cert  │
  │  GET_PUB_KEY(uid_charlie) → verifica cert│
  │                                           │
  │  group_key = AES-256 aleatória (32 B)   │
  │  enc_alice   = ECDH(group_key, pub_alice) │
  │  enc_bob     = ECDH(group_key, pub_bob)   │
  │  enc_charlie = ECDH(group_key, pub_charlie)│
  │                                           │
  │──── CREATE_GROUP {nome, [alice,bob,charlie],
  │       enc_keys: {alice: ..., bob: ..., charlie: ...}} ─▶│
  │◀─── {group_id} ──────────────────────────│
  │  save_group_key(group_id, group_key)     │
```

Quando Bob faz login e chama `GET_GROUPS`, o servidor indica que pertence a um grupo. O cliente busca `GET_GROUP_KEY` e decifra a sua cópia da `group_key` via ECDH. Todas as mensagens de grupo são cifradas/decifradas com `group_key` usando AES-256-GCM. O servidor entrega as mensagens apenas aos membros atuais do grupo.

O administrador pode adicionar membros (cifrando a `group_key` atual para o novo membro via ECDH) ou remover membros (o servidor deixa de entregar mensagens ao removido e faz uma rotação da chave para todos os restantes membros).

---

## 4. Gestão de Chaves

### 4.1 Master Seed

Cada utilizador possui uma *Master Seed* — 32 bytes aleatórios gerados no registo. Todas as chaves criptográficas do utilizador são derivadas deterministicamente desta seed, permitindo recuperar o estado em qualquer dispositivo conhecendo apenas a password.

```
Master Seed (32 B aleatórios)
      │
      ├─ HKDF(info="identity-key")       → priv_X25519  (chave de identidade)
      └─ HKDF(info="contact-key-storage") → storage_key  (protecção local)
```

A Master Seed é cifrada com AES-256-GCM antes de ser armazenada:

```
pwd_key = PBKDF2-HMAC-SHA256(password, salt, 150 000 iter)
enc_seed = AES-256-GCM(pwd_key, nonce, master_seed)
blob = base64(salt[16] ‖ nonce[12] ‖ enc_seed)
```

O `blob` é guardado no servidor (para sincronização entre dispositivos) e localmente. Em memória, a seed existe apenas enquanto o utilizador está autenticado — é apagada no logout.

### 4.2 Chaves de Contacto

Para cada par de contactos existe uma chave simétrica AES-256 (`sym_key`), gerada aleatoriamente pelo iniciador da relação. Esta chave é:

- **Cifrada para o destinatário** via ECDH efémero: `base64(eph_pub[32] ‖ nonce[12] ‖ AES-GCM(HKDF(X25519(eph, pub_dest), "contact-key-exchange"), sym_key))`
- **Cifrada para o próprio** via `storage_key`: `base64(nonce[12] ‖ AES-GCM(storage_key, sym_key))`

Localmente, as chaves de contacto são guardadas cifradas em `<username>_contacts.json`, protegidas pela `storage_key` derivada da Master Seed.

### 4.3 Chaves de Grupo

Cada grupo possui uma chave simétrica AES-256 (`group_key`), gerada pelo criador. É distribuída a cada membro via ECDH efémero com `info="group-key-exchange"` (para separação de domínio relativamente às chaves de contacto). Localmente, é guardada cifrada em `<username>_groups.json` com a `storage_key`.
A remoção de membros do grupo despoleta a rotação da chave pelo administrador e subsequente reencaminhamento para os restantes membros.

### 4.4 Separação de Domínio (Domain Separation)

Todas as derivações HKDF usam etiquetas (`info`) distintas para garantir que chaves derivadas do mesmo segredo para fins diferentes são criptograficamente independentes:

| Label HKDF | Utilização |
|------------|-----------|
| `"chat-session-key"` | Chave de sessão TLS do canal |
| `"identity-key"` | Par X25519 de identidade |
| `"contact-key-storage"` | Protecção local de chaves de contacto |
| `"contact-key-exchange"` | Troca de chave simétrica entre dois utilizadores |
| `"group-key-exchange"` | Distribuição de chave de grupo |

### 4.5 Identidade Opaca

O username nunca circula em claro entre o cliente e o servidor. O identificador público de cada utilizador é `SHA-256(username)` em hexadecimal (`uid`). O username real é trocado entre os dois clientes cifrado com a `sym_key` do par, e armazenado localmente no ficheiro de contactos de cada um.

---

## 5. Modelo de Segurança

### 5.1 Modelo de Ameaça

O sistema foi desenhado considerando dois adversários distintos:

**Servidor honesto mas curioso:** Executa o protocolo corretamente (não apaga nem altera mensagens indevidamente) mas tenta aprender o máximo possível sobre os utilizadores e as suas comunicações. Não deve conseguir ler o conteúdo das mensagens nem os nomes dos participantes nas conversas.

**Atacante aivo na rede (MITM):** Pode intercetar, modificar ou injetar pacotes TCP. Deve ser impedido de: (1) ler ou alterar mensagens, (2) fazer-se passar pelo servidor, (3) substituir chaves públicas de utilizadores.

### 5.2 Primitivas Criptográficas e Justificação

| Primitiva | Parâmetros | Justificação |
|-----------|-----------|-------------|
| X25519 (ECDH) | Curva 25519 | Troca de chaves eficiente e segura; resistente a ataques de timing por design |
| Ed25519 (assinaturas) | Curva 25519 | Assinaturas determinísticas, rápidas, resistentes a ataques de nonce |
| AES-256-GCM | 256 bits, nonce 96 bits | Cifra autenticada — garante simultaneamente confidencialidade e integridade |
| HKDF-SHA256 | — | Derivação de chaves a partir de segredos partilhados; separa domínios via `info` |
| PBKDF2-HMAC-SHA256 | 150 000 iterações, salt 128 bits | Derivação lenta de chave a partir de password; mitiga ataques de dicionário offline |
| SHA-256 | — | Identificador opaco de utilizador (não reversível) |

### 5.3 Garantias de Segurança

**Confidencialidade das mensagens:** As mensagens são cifradas com AES-256-GCM com a chave simétrica E2EE, que o servidor nunca possui. O servidor armazena e encaminha apenas ciphertext opaco.

**Integridade e autenticidade das mensagens:** AES-256-GCM inclui um tag de autenticação de 128 bits. Qualquer modificação do ciphertext em trânsito ou no servidor é detetada aquando da decifra pelo destinatário.

**Autenticidade do servidor:** O handshake inclui uma assinatura Ed25519 do servidor sobre a sua chave efémera X25519. O cliente verifica esta assinatura com a `signing_pub` fixada via TOFU, impedindo que um MITM substitua o servidor.

**Autenticidade das chaves de utilizadores (PKI):** Cada chave pública X25519 é acompanhada de um certificado assinado pela CA do servidor (Ed25519). O cliente verifica o certificado antes de usar qualquer chave pública para cifrar uma chave de contacto ou grupo, garantindo que mesmo um servidor comprometido em runtime não pode substituir chaves publicas de utilizadores sem invalidar a assinatura da CA.

**Privacidade de identidade:** O servidor nunca recebe usernames em claro. Os UIDs (SHA-256 do username) são não-reversíveis sem conhecer o username de antemão. Os usernames reais são trocados cifrados com a chave E2EE do par.

**Protecção da Master Seed:** A Master Seed é cifrada com uma chave derivada da password via PBKDF2 (150 000 iterações, salt aleatório de 128 bits). Um atacante com acesso ao ficheiro ou ao servidor necessita de um ataque de dicionário com custo proporcional ao número de iterações por tentativa.

**Protecção em trânsito:** Todos os dados após o handshake são cifrados com AES-256-GCM com nonce aleatório gerado por mensagem. A camada de transporte impõe um limite de 64 KB por mensagem para mitigar alocação excessiva de memória.

**Controlo de acesso em grupos:** O servidor apenas entrega mensagens de grupo a membros atuais. A adição/remoção de membros é restrita ao administrador do grupo. Novos membros recebem a chave de grupo cifrada via ECDH, sem que o servidor tenha acesso à chave em claro.

### 5.4 Limitações Conhecidas

**Rotação de chave de grupo na remoção de membro:** Quando um membro é removido de um grupo, a chave de grupo não é rotacionada. Um membro removido que tenha guardado a chave localmente continua a ser capaz de decifrar mensagens futuras se as obtiver por outros meios (o servidor já não lhas entrega, mas o risco permanece). Key rotation requereria que o administrador cifrasse uma nova chave para todos os membros restantes, implicando N operações GET_PUB_KEY — uma melhoria identificada mas não implementada.

**Estado do servidor não cifrado:** O ficheiro `server_state.json` contém em plaintext o grafo de contactos entre utilizadores (UIDs), as listas de membros de grupos e os metadados de certificados. Um atacante com acesso ao disco do servidor pode inferir relações sociais, ainda que não consiga ler o conteúdo das mensagens. Cifrar o estado do servidor comprometeria a capacidade do servidor de processar pedidos, pelo que uma solução real exigiria uma base de dados com cifra ao nível das colunas ou um modelo de servidor oblivious.

**Sessão única por utilizador:** O servidor recusa uma segunda ligação para o mesmo UID enquanto a primeira está ativa. Múltiplos dispositivos simultâneos não são suportados.

**Sem revogação de certificados:** Não existe mecanismo de CRL (Certificate Revocation List) ou OCSP. Se a chave privada X25519 de um utilizador for comprometida, o servidor não tem forma de invalidar o certificado existente sem intervenção manual.

**Fetch de Mensagens Não Otimizado**: A operação FETCH_MESSAGES carece de otimização, pois descarrega sempre a totalidade do buffer disponível sem filtrar apenas o que ainda não foi lido pelo cliente. Para solucionar esta limitação, seria necessária a introdução de um sistema de IDs únicos por mensagem (Message IDs) e o controlo do estado de leitura.

**Ausência de limite de tentativas de login:** O servidor não implementa rate limiting nas tentativas de autenticação, o que torna o sistema vulnerável a ataques de força bruta sobre passwords.

---

## 6. Valorizações Implementadas

### 6.1 Mensagens Offline

O servidor armazena mensagens destinadas a utilizadores não ligados numa fila por utilizador (`_offline[uid]`). Quando o destinatário se liga e chama `FETCH_MESSAGES`, recebe todas as mensagens pendentes. As mensagens são armazenadas como ciphertext AES-256-GCM — o servidor nunca tem acesso ao conteúdo. O mesmo mecanismo aplica-se às mensagens de grupo (`_group_messages[uid][group_id]`), com filas independentes por grupo e por utilizador.

### 6.2 Entidade de Certificação (PKI)

O servidor funciona como CA self-signed usando Ed25519. No arranque, gera (ou carrega) um par de chaves de longa duração armazenado em `server/data/server_signing.pem`. No registo de cada utilizador, a CA emite um certificado digital:

```json
{ "pub_key": "<base64 X25519>", "uid": "<sha256 hex>" }
```

O JSON é serializado de forma canónica (chaves ordenadas lexicograficamente, sem espaços) para garantir que a assinatura é determinística e não depende da ordem de serialização. O certificado é armazenado no servidor e devolvido juntamente com a chave pública em resposta a pedidos `GET_PUB_KEY`.

O cliente verifica a assinatura Ed25519 em `common/ca.py` sempre que obtém a chave pública de um contacto ou membro de grupo antes de a usar em operações criptográficas. A chave de assinatura da CA já estava fixada via TOFU no handshake inicial — não é necessário nenhum canal adicional para a sua distribuição.

### 6.3 Mensagens de Grupo

Os grupos têm um identificador único (UUID4 hex), um nome, um administrador e uma lista de membros. A chave de grupo (AES-256) é gerada pelo criador e distribuída a cada membro via ECDH efémero com domain separation (`info="group-key-exchange"`), garantindo E2EE mesmo para grupos. O servidor gere as filas de entrega por membro e aplica controlo de acesso (apenas membros podem enviar; apenas o administrador pode gerir membros). O histórico local de mensagens de grupo é armazenado cifrado, usando a mesma infraestrutura do `MessageStore`.

---

## 7. Funcionalidades Não Implementadas

**Rotação de chave de grupo na remoção de membro:** Como descrito na secção de limitações, a remoção de um membro não rota a chave de grupo. Uma implementação correta desta feature requereria que o administrador obtivesse as chaves públicas de todos os membros restantes e re-cifrasse uma nova chave de grupo para cada um, o que implica N chamadas `GET_PUB_KEY` e distribui a carga para o cliente administrador.

---

## 8. Dependências

- **Python 3.10+**
- **`cryptography`** (versão ≥ 41) — X25519, Ed25519, AES-256-GCM, PBKDF2-HMAC-SHA256, HKDF-SHA256
