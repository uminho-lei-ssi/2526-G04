#!/bin/bash

set -e

GRUPO_SSI="grupo-ssi"
UTILIZADOR_GRUPO="a106877"

# Nota: caso getfacl/setfacl nao estejam instalados, executar:
# sudo apt update
# sudo apt install acl

# Exercicio 1
getfacl porto.txt

# Exercicio 2
sudo setfacl -m "g:${GRUPO_SSI}:w" porto.txt

# Exercicio 3
getfacl porto.txt
# Comentario: face ao ponto 1, surge uma entrada ACL especifica para o grupo
# grupo-ssi com permissao de escrita. Tambem pode aparecer/alterar-se a mascara
# ACL, que limita as permissoes efetivas das entradas de grupo e utilizadores
# nomeados.

# Exercicio 4
sudo -u "$UTILIZADOR_GRUPO" bash -c 'printf "Linha escrita via ACL\n" >> porto.txt'
sudo -u "$UTILIZADOR_GRUPO" cat porto.txt || true
# Comentario: a ACL atribuida concede escrita ao grupo, mas nao concede
# necessariamente leitura. Se o ficheiro mantiver apenas permissoes 500 do
# sec1.sh, o utilizador do grupo consegue escrever mas pode nao conseguir ler
# o conteudo, pois a leitura continua ausente para o grupo.
