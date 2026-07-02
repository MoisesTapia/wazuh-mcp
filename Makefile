.PHONY: install dev run test test-integration test-all lint check-tools \
        security security-deps security-licenses security-sast security-docker \
        certs docker-up docker-down docker-logs docker-status docker-reset \
        mcp-docker mcp-docker-down setup-claude-desktop wait-for-wazuh clean

VENV      = .venv
PYTHON    = $(VENV)/bin/python
PIP       = $(VENV)/bin/pip
PYTEST    = $(VENV)/bin/pytest
FASTMCP   = $(VENV)/bin/fastmcp

CERTS_DIR = config/wazuh_indexer_ssl_certs
TIMEOUT   ?= 180

# ── Instalación ───────────────────────────────────────────────────────────────

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	@echo ""
	@echo "Instalación completa. Activa el venv con:"
	@echo "  source $(VENV)/bin/activate"

# ── Desarrollo local ──────────────────────────────────────────────────────────

dev:
	$(FASTMCP) dev src/wazuh_mcp/server.py

run:
	$(FASTMCP) run src/wazuh_mcp/server.py

# ── Tests ─────────────────────────────────────────────────────────────────────

test:
	PYTHONPATH=src $(PYTEST) tests/ -v -k "not integration" --tb=short

test-integration:
	PYTHONPATH=src $(PYTEST) tests/test_auth_live.py -v -s

test-all:
	PYTHONPATH=src $(PYTEST) tests/ -v --tb=short

# ── Lint / Sintaxis ───────────────────────────────────────────────────────────

lint:
	$(PYTHON) -m py_compile \
		src/wazuh_mcp/client.py \
		src/wazuh_mcp/server.py \
		src/wazuh_mcp/auth.py \
		src/wazuh_mcp/config.py \
		src/wazuh_mcp/circuit_breaker.py \
		src/wazuh_mcp/tools/observability.py \
		src/wazuh_mcp/tools/agents.py \
		src/wazuh_mcp/tools/manager.py \
		src/wazuh_mcp/tools/security.py \
		src/wazuh_mcp/tools/rules.py \
		src/wazuh_mcp/tools/decoders.py \
		src/wazuh_mcp/tools/cluster.py \
		src/wazuh_mcp/tools/syscheck.py \
		src/wazuh_mcp/tools/syscollector.py \
		src/wazuh_mcp/tools/groups.py \
		src/wazuh_mcp/tools/mitre.py \
		src/wazuh_mcp/tools/sca.py \
		src/wazuh_mcp/tools/rootcheck.py \
		src/wazuh_mcp/tools/lists.py \
		src/wazuh_mcp/tools/logtest.py \
		src/wazuh_mcp/tools/active_response.py \
		src/wazuh_mcp/tools/active_response_soc.py \
		src/wazuh_mcp/tools/ciscat.py \
		src/wazuh_mcp/tools/events.py \
		src/wazuh_mcp/tools/overview.py \
		src/wazuh_mcp/tools/experimental.py
	@echo "Sin errores de sintaxis."

# Verifica que todas las tools registradas tienen docstring
check-tools:
	PYTHONPATH=src $(PYTHON) scripts/check_tools.py

# ── DevSecOps: escaneos de seguridad (reportes a consola) ─────────────────────
# Mismos escaneos que el workflow .github/workflows/devsecops.yml, en local.
# Requiere las herramientas: pip install pip-audit "bandit[toml]" pip-licenses
# y hadolint (o Docker) para el Dockerfile.
# Report-only: los scanners no fallan el target (igual que continue-on-error en CI).

security: security-deps security-licenses security-sast security-docker
	@echo ""
	@echo "Escaneos de seguridad completados."

# Vulnerabilidades en dependencias
security-deps:
	@echo "── Dependency scan (pip-audit) ───────────────────────────────"
	$(VENV)/bin/pip-audit --progress-spinner=off --desc || true

# Licencias de dependencias + aviso de copyleft/unknown
security-licenses:
	@echo "── License scan (pip-licenses) ───────────────────────────────"
	$(VENV)/bin/pip-licenses --order=license --format=markdown --with-urls
	@$(VENV)/bin/pip-licenses --format=csv | grep -iE 'GPL|AGPL|LGPL|MPL|UNKNOWN' \
		&& echo "AVISO: revisa las licencias copyleft/unknown de arriba." \
		|| echo "Sin licencias copyleft/unknown."

# SAST del código Python
security-sast:
	@echo "── SAST (bandit) ─────────────────────────────────────────────"
	$(VENV)/bin/bandit -r src/ -ll -f screen || true

# SAST/lint del Dockerfile (usa hadolint local, o Docker como fallback)
security-docker:
	@echo "── Dockerfile lint (hadolint) ────────────────────────────────"
	@if command -v hadolint >/dev/null 2>&1; then \
		hadolint Dockerfile || true; \
	else \
		docker run --rm -i -v "$(PWD)/.hadolint.yaml:/.hadolint.yaml" \
			hadolint/hadolint hadolint - < Dockerfile || true; \
	fi

# ── Certificados SSL ──────────────────────────────────────────────────────────

# Genera los certificados SSL necesarios para el indexer, manager y dashboard.
# Solo ejecutar la primera vez (o si quieres regenerar los certs).
certs:
	@echo "Generando certificados SSL para Wazuh..."
	docker compose -f generate-indexer-certs.yml run --rm generator
	@echo "Certificados generados en $(CERTS_DIR)/"

# Verifica que los certificados existen
_check-certs:
	@if [ ! -f "$(CERTS_DIR)/root-ca.pem" ]; then \
		echo ""; \
		echo "ERROR: Certificados SSL no encontrados en $(CERTS_DIR)/"; \
		echo "Ejecuta primero: make certs"; \
		echo ""; \
		exit 1; \
	fi

# ── Docker: stack completo (Manager + Indexer + Dashboard) ───────────────────

docker-up: _check-certs
	@echo "Iniciando stack de Wazuh (manager + indexer + dashboard)..."
	@echo "Nota: el primer arranque tarda ~3-4 minutos."
	docker compose up -d
	@./scripts/wait-for-wazuh.sh $(TIMEOUT)

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-logs-manager:
	docker compose logs -f wazuh.manager

docker-logs-indexer:
	docker compose logs -f wazuh.indexer

docker-logs-dashboard:
	docker compose logs -f wazuh.dashboard

docker-status:
	docker compose ps

# DESTRUCTIVO: para contenedores y elimina TODOS los volúmenes (datos permanentes)
docker-reset:
	@echo "ADVERTENCIA: Esto eliminará todos los datos de Wazuh (volúmenes Docker)."
	@read -p "¿Continuar? [s/N] " ans && [ "$$ans" = "s" ] || exit 0
	docker compose down -v
	@echo "Contenedores y volúmenes eliminados."

# ── Docker: stack completo + MCP Server ──────────────────────────────────────

mcp-docker: _check-certs
	docker compose --profile mcp up -d --build
	@echo ""
	@echo "MCP Server disponible en: http://localhost:8000/mcp/"
	@echo "Dashboard Wazuh en:       https://localhost"

mcp-docker-down:
	docker compose --profile mcp down

# ── Claude Desktop ────────────────────────────────────────────────────────────

setup-claude-desktop:
	@./scripts/setup-claude-desktop.sh

wait-for-wazuh:
	@./scripts/wait-for-wazuh.sh $(TIMEOUT)

# ── Limpieza ─────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.egg-info" -type d -exec rm -rf {} + 2>/dev/null || true
