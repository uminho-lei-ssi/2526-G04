#!/bin/bash

set -e

# Exercicio 1
printf "Lisboa e a capital de Portugal.\n" > lisboa.txt
printf "Porto fica no norte de Portugal.\n" > porto.txt
printf "Braga e uma cidade historica.\n" > braga.txt

# Exercicio 2
ls -l lisboa.txt
stat lisboa.txt

# Exercicio 3
chmod 666 lisboa.txt

# Exercicio 4
chmod 500 porto.txt

# Exercicio 5
chmod 400 braga.txt

# Exercicio 6
mkdir -p dir1 dir2
ls -ld dir1 dir2
stat dir1 dir2

# Exercicio 7
chmod go-x dir2
ls -ld dir2
