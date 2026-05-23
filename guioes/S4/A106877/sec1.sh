#!/bin/bash

set -e

# Semana 4 - Seccao 1: Capability leaking atraves de descritor de diretoria.
# Executar apenas numa VM/ambiente descartavel.

# Setup
gcc -Wall -Wextra -O2 -o backupssi backupssi.c
gcc -Wall -Wextra -O2 -o backupssi_fixed backupssi_fixed.c
sudo chown root:root backupssi backupssi_fixed
sudo chmod 4755 backupssi backupssi_fixed

# Exercicio 1
echo "Executar como utilizador normal:"
echo "./backupssi"

# Exercicio 2
# Analise:
# O programa abre /root enquanto ainda corre com euid=root, criando um descritor
# de ficheiro para uma diretoria protegida. Depois chama setuid(getuid()), mas
# nao fecha o descritor antes de executar /bin/sh. Esse descritor fica herdado
# pela shell sem privilegios. A vulnerabilidade e o capability leaking: a
# capacidade de aceder a /root fica representada no FD aberto e sobrevive a
# queda de privilegios.

# Exercicio 3
echo "Exploit demonstrativo:"
echo "./exploit_backupssi.sh"

# Exercicio 4
# Correcao:
# backupssi_fixed.c abre /root com O_CLOEXEC e fecha explicitamente o descritor
# com close(dfd) antes de setuid() e execve(). Assim, a shell posterior nao
# herda a referencia privilegiada a /root. O_CLOEXEC tambem impede que o FD
# atravesse execve caso um caminho de erro futuro se esqueca de o fechar.
echo "Executavel corrigido criado: ./backupssi_fixed"
