# Semana 4 - Demonstracao de Exploits Relativos a Controlo de Acesso

Executar estes exemplos apenas numa VM ou ambiente descartavel.

## 1. Capability leaking

```bash
./sec1.sh
./exploit_backupssi.sh
./backupssi_fixed
```

O problema esta no descritor de ficheiro aberto para `/root`. O programa baixa
privilegios, mas deixa o FD aberto e depois executa uma shell. A shell herda o
FD e consegue usar `/proc/self/fd/3` para aceder a uma diretoria que um
utilizador normal nao conseguiria abrir diretamente.

A versao corrigida usa `O_CLOEXEC` e `close(dfd)` antes de executar a shell.

## 2. Elevacao de privilegio

```bash
./sec2.sh
./exploit_passwdleak.sh
su ssihacker
```

O problema esta no FD aberto para escrita em `/etc/passwd`. A shell herdada
consegue escrever nesse FD, apesar de ja estar a correr com UID normal. O
exploit adiciona uma entrada com UID 0:

```text
ssihacker::0:0::/root:/bin/sh
```

A versao corrigida usa `O_CLOEXEC` e fecha o FD antes de `execl`.
