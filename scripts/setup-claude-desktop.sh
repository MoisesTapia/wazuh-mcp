#!/usr/bin/env bash
# Instala el MCP en Claude Desktop automáticamente.
# Usa fastmcp install para configurar claude_desktop_config.json.
# Ejecutar desde la raíz del proyecto con el venv activo.
#
# Uso:
#   source .venv/bin/activate
#   ./scripts/setup-claude-desktop.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
SERVER_FILE="${PROJECT_DIR}/src/wazuh_mcp/server.py"
ENV_FILE="${PROJECT_DIR}/.env"

if [ ! -f "${ENV_FILE}" ]; then
    echo "ERROR: .env no encontrado. Ejecuta primero: cp .env.example .env"
    exit 1
fi

# Carga el .env
set -a
source "${ENV_FILE}"
set +a

echo "Instalando Wazuh MCP en Claude Desktop..."
echo "  Servidor: ${SERVER_FILE}"
echo "  Wazuh:    https://${WAZUH_HOST:-localhost}:${WAZUH_PORT:-55000}"
echo ""

fastmcp install claude-desktop "${SERVER_FILE}" \
    --name "wazuh" \
    --env-file "${ENV_FILE}" \
    --with-editable "${PROJECT_DIR}"

echo ""
echo "Instalación completa."
echo "Reinicia Claude Desktop para que los cambios surtan efecto."
echo ""
echo "Verifica la configuración en:"
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "  ~/Library/Application Support/Claude/claude_desktop_config.json"
else
    echo "  ~/.config/Claude/claude_desktop_config.json"
fi
