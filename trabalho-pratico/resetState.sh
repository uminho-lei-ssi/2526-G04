#!/bin/bash

# =================================================================
# Script de Reset de Estado
# Limpa chaves, mensagens e caches para um ambiente de teste limpo.
# =================================================================

echo "--- A iniciar limpeza total do estado do projeto ---"

# Definir caminhos
CLIENT_STATE="client/data"
SERVER_STATE="server/data"

# Limpar dados do Cliente
echo "Limpando chaves e mensagens do cliente... "
rm -rf "$CLIENT_STATE"/* 2>/dev/null
rm -rf "$SERVER_STATE"/* 2>/dev/null
echo "OK"

echo "--- Limpeza concluída. Podes testar do zero. ---"