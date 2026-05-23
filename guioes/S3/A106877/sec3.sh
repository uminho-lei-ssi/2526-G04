#!/bin/bash

set -e

UTILIZADOR="userssi"

# Nota: se estiver numa sessao iniciada com outro utilizador, executar exit
# antes de correr esta seccao.

# Exercicio 1
gcc -Wall -Wextra -O2 -o leitor leitor.c

# Exercicio 2
if ! id "$UTILIZADOR" >/dev/null 2>&1; then
    sudo adduser --disabled-password --gecos "" "$UTILIZADOR"
fi

# Exercicio 3
sudo chown "$UTILIZADOR" leitor braga.txt
sudo chmod 755 leitor
sudo chmod 400 braga.txt

# Exercicio 4
./leitor braga.txt || true

# Exercicio 5
sudo chmod u+s leitor
ls -l leitor

# Exercicio 6
./leitor braga.txt || true
# Comentario: depois de ativar setuid no executavel, o utilizador efetivo do
# processo passa a ser o dono do ficheiro executavel, userssi. Como braga.txt
# tambem pertence a userssi e tem permissao de leitura para o dono, o programa
# consegue ler o ficheiro mesmo quando invocado por outro utilizador.
