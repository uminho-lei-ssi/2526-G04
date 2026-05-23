# Semana 7 - MACs e Cifras Autenticadas

## Programas

```bash
# Prefix-MAC com SHA256
python3 mac_sha256.py setup mac.key
python3 mac_sha256.py mac msg.txt mac.key
python3 mac_sha256.py ver msg.txt mac.key

# Ataque de length extension
python3 mac_sha256_attack.py msg.txt "&admin=true"
python3 mac_sha256.py ver msg.txt.ext mac.key

# AES-CTR + HMAC (encrypt-then-MAC)
printf "minha_pass" | python3 pbenc_aes_ctr_hmac.py enc msg.txt
printf "minha_pass" | python3 pbenc_aes_ctr_hmac.py dec msg.txt.enc

# AES-GCM (cifra autenticada)
printf "minha_pass" | python3 pbenc_aes_gcm.py enc msg.txt
printf "minha_pass" | python3 pbenc_aes_gcm.py dec msg.txt.enc
```

## Q1

Para o URL dado, o tamanho da mensagem e 62 bytes. Com chave de 32 bytes, a
entrada para o SHA256 tem 94 bytes (752 bits). O padding do SHA256 acrescenta
0x80, seguido de 25 bytes 0x00, e depois o comprimento em bits em 8 bytes:
`00 00 00 00 00 00 02 f0`. No total o padding tem 34 bytes.

## Q2

Em AES-CTR+HMAC o ficheiro guarda `salt (16) + nonce (16) + ciphertext + tag`
com um tag HMAC de 32 bytes. Em AES-GCM o ciphertext ja inclui um tag de 16
bytes e usa tipicamente nonce de 12 bytes. Assim, para a mesma mensagem, o
ficheiro em GCM e menor (menos 20 bytes no overhead fixo), porque o tag e o
nonce sao menores e integrados na cifra autenticada.
