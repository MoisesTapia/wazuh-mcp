#!/usr/bin/env bash
# Espera a que la API REST de Wazuh esté disponible y responda sin error.
#
# Uso: ./scripts/wait-for-wazuh.sh [timeout_segundos]
# Ejemplo: ./scripts/wait-for-wazuh.sh 180
#
# Lee WAZUH_HOST, WAZUH_PORT, WAZUH_USER, WAZUH_PASSWORD del entorno (o usa defaults).

set -euo pipefail

HOST="${WAZUH_HOST:-localhost}"
PORT="${WAZUH_PORT:-55000}"
USER="${WAZUH_USER:-wazuh-wui}"
PASS="${WAZUH_PASSWORD:-MyS3cr37P450r.*-}"
TIMEOUT="${1:-180}"
URL="https://${HOST}:${PORT}/"

echo "=========================================="
echo "  Esperando Wazuh API: ${URL}"
echo "  Timeout: ${TIMEOUT}s"
echo "=========================================="

deadline=$(( $(date +%s) + TIMEOUT ))
attempt=0

while true; do
    attempt=$(( attempt + 1 ))
    now=$(date +%s)

    if [ "$now" -ge "$deadline" ]; then
        echo ""
        echo "ERROR: Wazuh API no respondió en ${TIMEOUT}s (${attempt} intentos)."
        echo ""
        echo "Diagnóstico:"
        echo "  docker compose ps"
        echo "  docker compose logs wazuh.manager"
        echo "  docker compose logs wazuh.indexer"
        exit 1
    fi

    response=$(curl -sf -k -u "${USER}:${PASS}" "${URL}" 2>/dev/null || true)

    if echo "${response}" | grep -q '"error": 0'; then
        echo ""
        echo "✓ Wazuh API disponible (${attempt} intento(s))."
        echo ""
        echo "  Dashboard: https://localhost"
        echo "  API REST:  https://localhost:55000"
        echo "  Usuario:   admin / SecretPassword  (dashboard)"
        echo "  Usuario:   ${USER} / ***  (API REST / MCP)"
        echo ""
        exit 0
    fi

    printf "."
    sleep 5
done
