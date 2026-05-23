#!/bin/bash

set -e


EQUIPA=(a106877 membro2 membro3)
PAR=(a106877 membro2)
GRUPO_SSI="grupo-ssi"
PAR_SSI="par-ssi"
DONO_BRAGA="${EQUIPA[0]}"

# Exercicio 0
cat /etc/passwd
cat /etc/group

# Exercicio 1
for user in "${EQUIPA[@]}"; do
    if ! id "$user" >/dev/null 2>&1; then
        sudo adduser --disabled-password --gecos "" "$user"
    fi
done

# Exercicio 2
if ! getent group "$GRUPO_SSI" >/dev/null; then
    sudo groupadd "$GRUPO_SSI"
fi

if ! getent group "$PAR_SSI" >/dev/null; then
    sudo groupadd "$PAR_SSI"
fi

for user in "${EQUIPA[@]}"; do
    sudo usermod -aG "$GRUPO_SSI" "$user"
done

for user in "${PAR[@]}"; do
    sudo usermod -aG "$PAR_SSI" "$user"
done

# Exercicio 3
cat /etc/passwd
cat /etc/group
# Comentario: /etc/passwd passa a incluir as entradas dos novos utilizadores.
# /etc/group passa a incluir grupo-ssi e par-ssi, bem como a lista de membros
# associados a cada grupo.

# Exercicio 4
sudo chown "$DONO_BRAGA" braga.txt

# Exercicio 5
cat braga.txt || true

# Exercicio 6
sudo -iu "$DONO_BRAGA" pwd

# Exercicio 7
id "$DONO_BRAGA"
groups "$DONO_BRAGA"
# Comentario: id mostra o UID do utilizador, o GID do grupo principal e os
# grupos secundarios. groups lista os grupos a que o utilizador pertence,
# incluindo grupo-ssi e, se aplicavel, par-ssi.

# Exercicio 8
sudo -u "$DONO_BRAGA" cat braga.txt || true
# Comentario: como o ficheiro braga.txt ficou com permissoes 400 no sec1.sh e
# o dono foi alterado para DONO_BRAGA, esse utilizador consegue le-lo. Outros
# utilizadores comuns nao conseguem, por nao terem permissao de leitura.

# Exercicio 9
sudo -u "$DONO_BRAGA" bash -c 'cd dir2 && pwd' || true
# Comentario: dir2 ficou sem permissao de execucao para grupo e outros. A
# permissao x numa diretoria permite atravessa-la/entrar nela. Assim, so o dono
# da diretoria consegue fazer cd dir2, salvo alteracao posterior de dono ou
# permissoes.
