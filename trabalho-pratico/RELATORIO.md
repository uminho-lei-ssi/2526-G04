# Relatório — Projecto de Segurança de Sistemas Informáticos
**Grupo 04 · 2025/2026**

---

## 1. Descrição Geral

O projecto consiste numa aplicação de chat segura cliente-servidor implementada em Python com a biblioteca `cryptography`. O sistema garante *End-to-End Encryption* (E2EE) nas mensagens trocadas entre utilizadores, assegurando que o servidor — mesmo que comprometido — não consegue aceder ao conteúdo das comunicações nem identificar os participantes por nome. Para além da funcionalidade base, foram implementadas as valorizações de mensagens offline, PKI/CA, mensagens de grupo e rotação de chaves para *forward secrecy* parcial.

---

## 2. Arquitectura do Sistema

### 2.1 Visão Geral

O sistema segue um modelo cliente-servidor clássico com separação lógica estrita entre as três camadas:

```
┌─────────────────────────────────────────────────────┐
│  client/                                            │
│  ├── main.py          Ponto de entrada + TOFU       │
│  ├── controller.py    Lógica de negócio + E2EE      │
│  ├── interface.py     UI interactiva em terminal    │
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

O servidor corre em modo contínuo, aguardando ligações TCP. Cada ligação é tratada numa thread independente (`ClientSession`), que despacha comandos JSON recebidos através do canal seguro. O estado global (utilizadores, mensagens offline, contactos, grupos) é mantido em memória e persistido num ficheiro JSON (`server/data/server_state.json`). O servidor actua também como Autoridade de Certificação (CA), mantendo um par de chaves Ed25519 de longa duração (`server/data/server_signing.pem`).

### 2.3 Cliente

Cada instância do cliente corresponde a um utilizador. Após estabelecer o canal seguro com o servidor (handshake), o utilizador interage com uma interface de texto interactiva. Toda a lógica criptográfica reside no `controller.py` e no `keystore.py`; a interface (`interface.py`) é agnóstica relativamente à segurança.

### 2.4 Protocolo de Transporte

A comunicação TCP usa *length-prefixed framing*: cada mensagem é precedida de 4 bytes big-endian com o comprimento do payload. O transporte implementa uma verificação de tamanho máximo (64 KB) para mitigar ataques de alocação de memória. Todo o payload após o handshake é cifrado com AES-256-GCM.

---

## 3. Fluxos de Comunicação

### 3.1 Handshake e Estabelecimento do Canal Seguro

O handshake é executado em cada nova ligação TCP e autentica o servidor perante o cliente:

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

O cliente verifica a assinatura Ed25519 do servidor sobre a sua chave efémera X25519. Na primeira ligação, a `signing_pub` é aceite e guardada (*Trust On First Use*); nas ligações seguintes, é comparada com a versão guardada — qualquer divergência é tratada como possível ataque MITM e a ligação é terminada.

A chave de sessão `session_key` é derivada via HKDF-SHA256 sobre o segredo partilhado X25519 e usada para cifrar todas as mensagens subsequentes com AES-256-GCM (nonce aleatório de 12 bytes por mensagem).

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
  │──── REGISTER {uid, pwd, pub_key, blob} ──▶│
  │                                            │  cert = {uid, pub_key}
  │                                            │  sig  = Ed25519Sign(signing_key, cert)
  │                                            │  guarda {hash(pwd), pub_key, blob, cert, sig}
  │◀─── RESPONSE {ok: true} ──────────────────│
```

O servidor nunca vê o username em claro — recebe apenas o seu SHA-256. O blob cifrado (Master Seed protegida pela password) é guardado no servidor para permitir sincronização entre dispositivos.

### 3.3 Login

```
Cliente                                    Servidor
  │──── LOGIN {uid, pwd} ────────────────────▶│
  │                                            │  verifica PBKDF2(pwd) == hash_guardado
  │◀─── RESPONSE {ok, pub_key, blob} ─────────│
  │                                            │
  │  decifra blob com PBKDF2(pwd) → seed      │
  │  guarda seed em memória                   │
  │──── FETCH_MESSAGES {} ───────────────────▶│
  │◀─── {messages, contact_keys, key_rotations}
  │  processa contact_keys e rotações pendentes
```

Após login bem-sucedido, o cliente busca imediatamente as mensagens, chaves de contacto e rotações de chave pendentes para completar eventuais handshakes E2EE iniciados por outros utilizadores enquanto estava offline.

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

Após este handshake, todas as mensagens entre Alice e Bob são cifradas com `sym_key` usando AES-256-GCM antes de serem enviadas ao servidor. Esta chave pode ser posteriormente substituída por uma nova chave simétrica através do mecanismo de rotação descrito abaixo.

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

### 3.6 Rotação de Chaves 1-para-1 (*Forward Secrecy*)

Para reduzir o impacto de uma eventual exposição futura de uma chave de contacto, o cliente suporta rotação da `sym_key` usada nas conversas 1-para-1. Ao abrir uma conversa, o cliente tenta obter a chave pública certificada do contacto e gerar uma nova chave simétrica aleatória:

```
Alice                                      Servidor/Bob
  │  GET_PUB_KEY(uid_bob) → verifica cert   │
  │  new_sym_key = AES-256 aleatória        │
  │  eph_priv = X25519.generate()           │
  │  shared = X25519(eph_priv, pub_bob)     │
  │  aes = HKDF(shared, "contact-key-rotation")
  │  enc_blob = eph_pub‖nonce‖AES-GCM(aes, new_sym_key)
  │  guarda new_sym_key localmente          │
  │──── ROTATE_KEY {uid_bob, enc_blob} ────▶│
  │                                          │  guarda em key_rotations[bob][alice]
  │             Bob──── FETCH_MESSAGES ────▶│
  │             Bob◀─── {key_rotations: {alice: enc_blob}}
  │             Bob decifra e substitui sym_key
```

O servidor apenas armazena o pacote cifrado de rotação enquanto Bob ainda não o sincronizou. A derivação usa uma etiqueta HKDF diferente (`"contact-key-rotation"`) para separar este uso do handshake inicial de contactos.

### 3.7 PKI — Emissão e Verificação de Certificados

No registo, o servidor emite um certificado digital associando o UID à chave pública X25519 do utilizador:

```json
{ "pub_key": "<base64 X25519>", "uid": "<sha256 hex>" }
```

O certificado é serializado em JSON canónico (chaves ordenadas, sem espaços) e assinado com a chave Ed25519 de longa duração do servidor. Esta assinatura é verificada pelo cliente sempre que obtém a chave pública de um contacto (fluxo `GET_PUB_KEY`), usando a `signing_pub` fixada via TOFU. Desta forma, mesmo que o servidor seja comprometido em memória, não pode substituir a chave pública de um utilizador sem invalidar a assinatura — a chave privada Ed25519 seria necessária para forjar um certificado válido.

### 3.8 Mensagens de Grupo

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

Quando Bob faz login e chama `GET_GROUPS`, o servidor indica que pertence a um grupo. O cliente busca `GET_GROUP_KEY` e decifra a sua cópia da `group_key` via ECDH. Todas as mensagens de grupo são cifradas/decifradas com `group_key` usando AES-256-GCM. O servidor entrega as mensagens apenas aos membros actuais do grupo.

O administrador pode adicionar membros (cifrando a `group_key` actual para o novo membro via ECDH) ou remover membros. Após remover um membro, o cliente administrador gera uma nova chave de grupo, cifra-a para todos os membros restantes e envia-a ao servidor através de `ROTATE_GROUP_KEY`. Desta forma, o membro removido deixa de receber mensagens novas e também deixa de possuir a chave necessária para as decifrar caso as obtenha por outro meio.

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

A chave de contacto pode ser rotacionada durante a utilização da conversa. Nesse caso, é gerada uma nova `sym_key`, guardada localmente pelo emissor e enviada cifrada para o destinatário com ECDH efémero usando `info="contact-key-rotation"`. Quando o destinatário sincroniza `FETCH_MESSAGES`, processa a rotação pendente e substitui a chave antiga pela nova.

### 4.3 Chaves de Grupo

Cada grupo possui uma chave simétrica AES-256 (`group_key`), gerada pelo criador. É distribuída a cada membro via ECDH efémero com `info="group-key-exchange"` (para separação de domínio relativamente às chaves de contacto). Localmente, é guardada cifrada em `<username>_groups.json` com a `storage_key`.

Quando um membro é removido, o administrador gera uma nova `group_key` e cifra-a de novo para todos os membros que permanecem no grupo. O servidor apenas substitui o mapa `enc_keys` associado ao grupo; nunca vê a nova chave em claro.

### 4.4 Separação de Domínio (Domain Separation)

Todas as derivações HKDF usam etiquetas (`info`) distintas para garantir que chaves derivadas do mesmo segredo para fins diferentes são criptograficamente independentes:

| Label HKDF | Utilização |
|------------|-----------|
| `"chat-session-key"` | Chave de sessão TLS do canal |
| `"identity-key"` | Par X25519 de identidade |
| `"contact-key-storage"` | Protecção local de chaves de contacto |
| `"contact-key-exchange"` | Troca de chave simétrica entre dois utilizadores |
| `"contact-key-rotation"` | Rotação da chave simétrica de uma conversa 1-para-1 |
| `"group-key-exchange"` | Distribuição de chave de grupo |

### 4.5 Identidade Opaca

O username nunca circula em claro entre o cliente e o servidor. O identificador público de cada utilizador é `SHA-256(username)` em hexadecimal (`uid`). O username real é trocado entre os dois clientes cifrado com a `sym_key` do par, e armazenado localmente no ficheiro de contactos de cada um.

---

## 5. Modelo de Segurança

### 5.1 Modelo de Ameaça

O sistema foi desenhado considerando dois adversários distintos:

**Servidor honesto mas curioso:** Executa o protocolo correctamente (não apaga nem altera mensagens indevidamente) mas tenta aprender o máximo possível sobre os utilizadores e as suas comunicações. Não deve conseguir ler o conteúdo das mensagens nem os nomes dos participantes nas conversas.

**Atacante activo na rede (MITM):** Pode interceptar, modificar ou injectar pacotes TCP. Deve ser impedido de: (1) ler ou alterar mensagens, (2) fazer-se passar pelo servidor, (3) substituir chaves públicas de utilizadores.

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

**Integridade e autenticidade das mensagens:** AES-256-GCM inclui um tag de autenticação de 128 bits. Qualquer modificação do ciphertext em trânsito ou no servidor é detectada aquando da decifra pelo destinatário.

**Autenticidade do servidor:** O handshake inclui uma assinatura Ed25519 do servidor sobre a sua chave efémera X25519. O cliente verifica esta assinatura com a `signing_pub` fixada via TOFU, impedindo que um MITM substitua o servidor.

**Autenticidade das chaves de utilizadores (PKI):** Cada chave pública X25519 é acompanhada de um certificado assinado pela CA do servidor (Ed25519). O cliente verifica o certificado antes de usar qualquer chave pública para cifrar uma chave de contacto ou grupo, garantindo que mesmo um servidor comprometido em runtime não pode substituir chaves públicas de utilizadores sem invalidar a assinatura da CA.

**Privacidade de identidade:** O servidor nunca recebe usernames em claro. Os UIDs (SHA-256 do username) são não-reversíveis sem conhecer o username de antemão. Os usernames reais são trocados cifrados com a chave E2EE do par.

**Protecção da Master Seed:** A Master Seed é cifrada com uma chave derivada da password via PBKDF2 (150 000 iterações, salt aleatório de 128 bits). Um atacante com acesso ao ficheiro ou ao servidor necessita de um ataque de dicionário com custo proporcional ao número de iterações por tentativa.

**Protecção em trânsito:** Todos os dados após o handshake são cifrados com AES-256-GCM com nonce aleatório gerado por mensagem. A camada de transporte impõe um limite de 64 KB por mensagem para mitigar alocação excessiva de memória.

**Controlo de acesso em grupos:** O servidor apenas entrega mensagens de grupo a membros actuais. A adição/remoção de membros é restrita ao administrador do grupo. Novos membros recebem a chave de grupo cifrada via ECDH, sem que o servidor tenha acesso à chave em claro.

**Forward secrecy parcial:** O canal cliente-servidor usa ECDH efémero por ligação. Nas conversas 1-para-1, a chave E2EE pode ser rotacionada quando a conversa é aberta, sendo a nova chave enviada cifrada para o contacto. Nos grupos, a chave é rotacionada após remoção de membros, impedindo que membros removidos continuem a decifrar mensagens futuras apenas por terem guardado a chave antiga.

### 5.4 Limitações Conhecidas

**Forward secrecy incompleta face a Double Ratchet:** A rotação implementada é por evento/conversa, não por mensagem. Se uma chave de contacto for comprometida antes de uma nova rotação ser recebida pelo destinatário, as mensagens cifradas com essa chave continuam expostas. Uma protecção mais forte exigiria um protocolo de ratchet por mensagem, com encadeamento de chaves e recuperação após compromisso.

**Mensagens antigas após rotação:** O cliente mantém localmente a chave de contacto actual. Depois de uma rotação, mensagens antigas que ainda não tenham sido decifradas podem deixar de ser legíveis se dependerem da chave anterior. Um sistema completo teria de guardar versões de chaves por época ou associar cada mensagem a um identificador de chave.

**Estado do servidor não cifrado:** O ficheiro `server_state.json` contém em plaintext o grafo de contactos entre utilizadores (UIDs), as listas de membros de grupos e os metadados de certificados. Um atacante com acesso ao disco do servidor pode inferir relações sociais, ainda que não consiga ler o conteúdo das mensagens. Cifrar o estado do servidor comprometeria a capacidade do servidor de processar pedidos, pelo que uma solução real exigiria uma base de dados com cifra ao nível das colunas ou um modelo de servidor oblivious.

**Sessão única por utilizador:** O servidor recusa uma segunda ligação para o mesmo UID enquanto a primeira está activa. Múltiplos dispositivos simultâneos não são suportados.

**Sem verificação de revogação de certificados:** Não existe mecanismo de CRL (Certificate Revocation List) ou OCSP. Se a chave privada X25519 de um utilizador for comprometida, o servidor não tem forma de invalidar o certificado existente sem intervenção manual.

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

### 6.4 Forward Secrecy Parcial

Foi implementada rotação de chaves para conversas 1-para-1 e para grupos. Em conversas directas, ao abrir a conversa, o cliente gera uma nova chave simétrica e envia-a cifrada para o contacto através do comando `ROTATE_KEY`; o servidor guarda apenas o pacote cifrado em `key_rotations` até ao próximo `FETCH_MESSAGES` do destinatário. Em grupos, após remover um membro, o administrador gera uma nova `group_key`, cifra-a para todos os membros restantes e actualiza o servidor com `ROTATE_GROUP_KEY`.

Esta solução não equivale a um Double Ratchet completo, mas limita a exposição de mensagens futuras após rotação e melhora a segurança relativamente ao modelo anterior, em que as chaves de contacto e de grupo permaneciam estáticas por toda a relação.

---

## 7. Funcionalidades Não Implementadas

**Forward Secrecy completa (Double Ratchet):** Uma implementação completa exigiria a adopção de um protocolo de ratchet (semelhante ao Signal Protocol), com geração de novas chaves por mensagem, chaves por época e possibilidade de healing após comprometimento de uma chave. A solução actual implementa rotação explícita de chaves, mas não um ratchet contínuo por mensagem.

**Modo Descentralizado (PGP-like / P2P):** A arquitectura actual é intrinsecamente centralizada — o servidor é o único ponto de encontro entre clientes. Um modo P2P exigiria mecanismos de descoberta de endereços (ex.: NAT traversal, servidor de sinalização separado) e um protocolo de handshake directo entre clientes, representando uma mudança arquitectural significativa.

---

## 8. Dependências

- **Python 3.10+**
- **`cryptography`** (versão ≥ 41) — X25519, Ed25519, AES-256-GCM, PBKDF2-HMAC-SHA256, HKDF-SHA256
