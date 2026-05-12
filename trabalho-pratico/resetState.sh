#!/bin/bash

# =================================================================
# Script de Reset de Estado
# Limpa chaves, mensagens e caches para um ambiente de teste limpo.
# =================================================================

echo "--- A iniciar limpeza total do estado do projeto ---"

# Definir caminhos
CLIENT_KEYS="client/data/keys"
CLIENT_MSGS="client/data/messages"
SERVER_STATE="server/data"

# Limpar dados do Cliente
echo "Limpando chaves e mensagens do cliente... "
rm -rf "$CLIENT_KEYS"/* 2>/dev/null
rm -rf "$CLIENT_MSGS"/* 2>/dev/null
rm -rf "$SERVER_STATE"/* 2>/dev/null
echo "OK"

echo "--- Limpeza concluída. Podes testar do zero. ---"