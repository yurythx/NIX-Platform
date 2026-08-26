.PHONY: dev up down logs build test lint format \
	migrate-up migrate-down migrate-status seed-admin \
	backend-shell frontend-shell rabbitmq-status clean \
	backend-build backend-test backend-lint backend-format \
	frontend-build frontend-test frontend-lint frontend-format

# Carrega DB_USER/DB_PASSWORD/DB_NAME/... do .env quando presente, para que
# os alvos `make migrate-*` apontem para o mesmo banco usado pela aplicação.
ifneq (,$(wildcard .env))
include .env
export
endif

COMPOSE      := docker compose -f docker-compose.yml -f docker-compose.dev.yml
COMPOSE_PROD := docker compose -f docker-compose.yml
GOOSE_DIR    := backend/migrations
DB_USER      ?= nix
DB_PASSWORD  ?= change-me
DB_NAME      ?= nix
DB_DSN       ?= postgres://$(DB_USER):$(DB_PASSWORD)@localhost:5432/$(DB_NAME)?sslmode=disable

## --- Orquestração local ---

dev: ## Sobe todos os serviços em modo desenvolvimento (com overrides de dev)
	$(COMPOSE) up --build

up: ## Sobe todos os serviços em modo produção
	$(COMPOSE_PROD) up --build -d

down: ## Para e remove todos os serviços
	$(COMPOSE) down

logs: ## Acompanha os logs de todos os serviços
	$(COMPOSE) logs -f

clean: ## Para os serviços e remove os volumes (DESTRÓI os dados locais)
	$(COMPOSE) down -v

## --- Build ---

build: backend-build frontend-build ## Compila os binários/artefatos do backend e do frontend

backend-build:
	cd backend && go build ./...

frontend-build:
	cd frontend && npm run build

## --- Testes ---

test: backend-test frontend-test ## Roda as suítes de teste do backend e do frontend

backend-test:
	# -p 1: os testes de vários pacotes exercitam um PostgreSQL/RabbitMQ
	# real e compartilhado (TEST_DATABASE_URL/TEST_RABBITMQ_URL), não
	# mocks. Rodar os binários de teste de cada pacote em paralelo
	# (padrão do go test) permite que linhas/mensagens ao vivo de um
	# pacote vazem para as asserções de outro — por isso serializamos.
	cd backend && go test ./... -p 1

frontend-test:
	cd frontend && npm test

## --- Lint / format ---

lint: backend-lint frontend-lint ## Roda lint no backend e no frontend

backend-lint:
	cd backend && go vet ./...

frontend-lint:
	cd frontend && npm run lint

format: backend-format frontend-format ## Formata o backend e o frontend

backend-format:
	cd backend && go fmt ./...

frontend-format:
	cd frontend && npm run format

## --- Segurança ---

secscan: ## Builda e roda o nix-secscan (Fase 8 do roadmap de segurança) contra o repositório inteiro
	# Cada linha de receita do Make roda num subshell próprio — o "cd
	# backend" da primeira linha não vaza pra segunda, que por isso já
	# roda a partir da raiz do repo (onde "--repo ." precisa apontar,
	# pra cobrir backend/ e frontend/ juntos).
	cd backend && go build -o /tmp/nix-secscan ./cmd/secscan
	/tmp/nix-secscan scan --repo . --scanners trivy,semgrep --fail-on HIGH

## --- Migrations (Goose) ---

migrate-up: ## Aplica todas as migrations pendentes
	cd $(GOOSE_DIR) && goose postgres "$(DB_DSN)" up

migrate-down: ## Reverte a última migration
	cd $(GOOSE_DIR) && goose postgres "$(DB_DSN)" down

migrate-status: ## Mostra o status das migrations
	cd $(GOOSE_DIR) && goose postgres "$(DB_DSN)" status

seed-admin: ## Cria/reseta o usuário admin local com senha ALEATÓRIA (impressa só uma vez)
	# A migration 000027 removeu o admin/Admin123! semeado antes (senha
	# conhecida publicamente, achado de auditoria de segurança) — este é
	# o jeito correto de repor um admin local: DB_HOST/DB_PORT apontam pro
	# Postgres exposto por docker-compose.dev.yml (localhost:5432), o
	# resto vem do .env.
	cd backend && DB_HOST=localhost DB_PORT=5432 DB_NAME=$(DB_NAME) DB_USER=$(DB_USER) DB_PASSWORD=$(DB_PASSWORD) \
		go run ./cmd/seedadmin

## --- Shells ---

backend-shell: ## Abre um shell no container backend-api em execução
	$(COMPOSE) exec backend-api sh

frontend-shell: ## Abre um shell no container frontend em execução
	$(COMPOSE) exec frontend sh

## --- RabbitMQ ---

rabbitmq-status: ## Mostra o status do nó/filas do RabbitMQ
	$(COMPOSE) exec rabbitmq rabbitmqctl status
