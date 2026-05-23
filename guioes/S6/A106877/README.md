# Semana 6 - Cifras Modernas

## Programas

```bash
# ChaCha20 com chave em ficheiro
python3 cfich_chacha20.py setup chacha.key
python3 cfich_chacha20.py enc ptxt.txt chacha.key
python3 cfich_chacha20.py dec ptxt.txt.enc chacha.key

# Ataque de integridade (stream cipher)
python3 chacha20_int_attck.py ptxt.txt.enc 5 "mundo" "terra"

# AES-CBC
python3 cfich_aes_cbc.py setup aes.key
python3 cfich_aes_cbc.py enc ptxt.txt aes.key
python3 cfich_aes_cbc.py dec ptxt.txt.enc aes.key

# AES-CTR
python3 cfich_aes_ctr.py setup aes.key
python3 cfich_aes_ctr.py enc ptxt.txt aes.key
python3 cfich_aes_ctr.py dec ptxt.txt.enc aes.key

# ChaCha20 com password-based encryption
printf "minha_pass" | python3 pbenc_chacha20.py enc ptxt.txt
printf "minha_pass" | python3 pbenc_chacha20.py dec ptxt.txt.enc
```

## Q1

Usar um nonce fixo faz com que o fluxo de chave se repita. Isso equivale a um
"two-time pad": `C1 xor C2 = P1 xor P2`, expondo relacoes entre mensagens e
permitindo ataques por palavras provaveis. A confidencialidade fica quebrada.

## Q2

Num stream cipher sincrono, um bit de entrada influencia apenas o bit
correspondente do criptograma. Portanto, ao alterar 1 bit do texto-limpo e
cifrar com a mesma chave e nonce, altera-se exatamente 1 bit no criptograma na
mesma posicao.

## Q3

- CBC: ao alterar 1 bit de um bloco do criptograma, o bloco de texto-limpo
  correspondente fica totalmente corrompido (efeito avalancha) e o mesmo bit
  e invertido no bloco seguinte. Logo afeta 2 blocos (um inteiro + 1 bit).
- CTR: ao alterar 1 bit do criptograma, apenas esse bit e invertido no
  texto-limpo na mesma posicao.

## Q4

O ataque `chacha20_int_attck.py` funciona para cifras do tipo stream, como
ChaCha20 e AES-CTR, porque o criptograma e `P xor K` e e possivel forcar um
novo texto-limpo ajustando diretamente os bits do criptograma. Em AES-CBC o
mesmo script nao produz o resultado pretendido: a alteracao num bloco afeta
um bloco inteiro e ainda um bit do bloco seguinte, sendo necessario um ataque
especifico a CBC (alterar o bloco anterior) para controlar bits do texto-limpo.

## Q5

O salt e usado na derivacao da chave (KDF) para evitar chaves repetidas e
prevenir ataques por tabelas precomputadas. O nonce e usado pela cifra para
garantir que o fluxo de chave nao se repete para a mesma chave. Sao coisas
independentes e ambos sao necessarios: o salt protege a derivacao da chave e o
nonce protege a cifra quando a mesma chave for reutilizada.
