# Semana 5 - Cifras Classicas

## Programas

```bash
python3 cesar.py enc G "CartagoEstaNoPapo"
python3 cesar.py dec G "IGXZGMUKYZGTUVGVU"
python3 cesar_attack.py "IGXZGMUKYZGTUVGVU" BACO PAPO

python3 vigenere.py enc BACO "CifraIndecifravel"
python3 vigenere.py dec BACO "DIHFBIPRFCKTSAXSM"
python3 vigenere_attack.py 3 "PGRGARHSFHPRGCVHOJHWEPZRSCJFIVSOFRWUTBKPZGGOZPZLHWKPBR" PAPO PRAIA

python3 otp.py setup 30 otp.key
echo "Mensagem a cifrar" > ptxt.txt
python3 otp.py enc ptxt.txt otp.key > ptxt.txt.enc
python3 otp.py dec ptxt.txt.enc otp.key > ptxt.txt.enc.dec

python3 bad_otp.py setup 30 bad.key
python3 bad_otp.py enc ptxt.txt bad.key > ptxt.txt.bad.enc
python3 bad_otp_attack.py 30 ptxt.txt.bad.enc Mensagem cifrar
```

## Q1

O comportamento funcional parece igual: ambos geram uma chave, cifram com XOR e
decifram aplicando novamente XOR. A diferenca esta na seguranca da chave. Em
`otp.py`, a chave e gerada com `os.urandom`, adequado para uso criptografico. Em
`bad_otp.py`, a chave vem de `random` com uma semente de apenas 2 bytes, ficando
limitada a 2^16 possibilidades. Isto torna a chave pesquisavel por forca bruta.

## Q2

Nao entra em contradicao com a seguranca absoluta do one-time pad. Esse resultado
assume uma chave verdadeiramente aleatoria, uniforme, secreta, tao longa como a
mensagem e usada uma unica vez. O ataque explora a falha na geracao da chave:
existem apenas 2^16 chaves possiveis, logo a hipotese de aleatoriedade perfeita
nao se verifica.

## Q3

Se duas mensagens forem cifradas com a mesma chave, entao `C1 xor C2 = P1 xor
P2`, porque a chave cancela. Isto revela relacoes entre os textos limpos e
permite ataques por palavras provaveis, repeticoes, formatos conhecidos e
tentativas de arrastamento de palavras. O ataque torna-se bastante pratico
quando as mensagens sao texto natural ou contem cabecalhos/estruturas previsiveis.
