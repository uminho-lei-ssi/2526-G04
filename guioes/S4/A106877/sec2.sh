#!/bin/bash

set -e

# Semana 4 - Seccao 2: Elevacao de privilegio atraves de FD vazado para
# /etc/passwd. Executar apenas numa VM/ambiente descartavel.

# Setup
gcc -Wall -Wextra -O2 -o passwdleak passwdleak.c
gcc -Wall -Wextra -O2 -o passwdleak_fixed passwdleak_fixed.c
sudo chown root:root passwdleak passwdleak_fixed
sudo chmod 4755 passwdleak passwdleak_fixed

# Exercicio 1
echo "Executar como utilizador normal:"
echo "./passwdleak"

# Exercicio 2
# Analise:
# O programa abre /etc/passwd para escrita enquanto tem euid=root. Depois baixa
# privilegios com setuid(getuid()), mas deixa o FD aberto e executa /bin/sh. A
# shell sem privilegios herda um descritor com permissao de escrita em
# /etc/passwd, permitindo alterar esse ficheiro protegido.

# Exercicio 3
echo "Exploit demonstrativo em bash:"
echo "./exploit_passwdleak.sh"

# Exercicio 4
# Implicacoes:
# A linha ssihacker::0:0::/root:/bin/sh cria uma conta sem password com UID 0 e
# GID 0. Na pratica, o atacante pode tentar iniciar sessao com su ssihacker e
# obter uma shell com privilegios equivalentes aos de root. Isto permite ler,
# modificar e apagar ficheiros do sistema, criar novos utilizadores, instalar
# software e persistir no sistema.

# Exercicio 5
# Correcao:
# passwdleak_fixed.c usa O_CLOEXEC e fecha explicitamente o FD antes de executar
# a shell. Assim, a shell posterior nao herda capacidade de escrita sobre
# /etc/passwd. Em codigo real, tambem se deve evitar abrir /etc/passwd
# diretamente e preferir ferramentas/ APIs apropriadas de gestao de contas.
echo "Executavel corrigido criado: ./passwdleak_fixed"
