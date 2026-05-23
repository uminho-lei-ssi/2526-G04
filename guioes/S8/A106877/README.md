# Semana 8 - Criptografia Asimetrica

## Programas

```bash
python3 dh.py
python3 dh_aes_gcm.py

# Gerar certificados (executar uma vez)
openssl genrsa -out CA.key 2048
openssl genrsa -out Alice.key 2048
openssl genrsa -out Bob.key 2048
openssl req -x509 -new -nodes -key CA.key -sha256 -days 365 -out CA.crt -subj "/CN=CA"
openssl req -new -key Alice.key -out Alice.csr -subj "/CN=Alice"
openssl x509 -req -in Alice.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out Alice.crt -days 365 -sha256
openssl req -new -key Bob.key -out Bob.csr -subj "/CN=Bob"
openssl x509 -req -in Bob.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out Bob.crt -days 365 -sha256

python3 sts_aes_gcm.py
```

## Q1

Se varias mensagens forem cifradas com chaves derivadas do mesmo segredo DH,
comprometer esse segredo permite reconstruir todas essas chaves e decifrar as
mensagens. Portanto, nao ha PFS para varias mensagens sob o mesmo segredo. A
PFS so e obtida quando se usam pares DH efemeros por sessao e se apagam chaves
intermedias depois do uso.

## Q2

As chaves publicas de cada participante estao armazenadas nos respetivos
certificados X509 (Alice.crt e Bob.crt). A chave publica da CA esta no
certificado da CA (CA.crt).

## Q3

Nao. Sem validar o certificado do Bob, a Alice pode aceitar um certificado
forjado por um atacante e validar uma assinatura feita com essa chave falsa.
Isso permite um ataque MITM, porque a assinatura deixa de estar ligada a uma
identidade autenticada pela CA.
