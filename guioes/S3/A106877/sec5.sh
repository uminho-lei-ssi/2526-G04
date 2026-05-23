#!/bin/bash

set -e

# Exercicio 1
capsh --print

# Exercicio 2
gcc -Wall -Wextra -O2 -o webserver webserver.c
./webserver 4050

# Exercicio 3
./webserver 80 || true
# Comentario: em Linux, portas TCP/UDP inferiores a 1024 sao tradicionalmente
# privilegiadas. Um utilizador comum normalmente nao consegue fazer bind a
# porta 80 sem privilegios adicionais. Em sistemas recentes, a configuracao
# net.ipv4.ip_unprivileged_port_start pode alterar esse comportamento.

# Como usar capabilities em vez de setuid root:
sudo setcap cap_net_bind_service=+ep ./webserver
getcap ./webserver
./webserver 80 || true
# Comentario: CAP_NET_BIND_SERVICE permite ao executavel fazer bind a portas
# inferiores a 1024 sem executar o programa como root completo, respeitando o
# principio do menor privilegio.
