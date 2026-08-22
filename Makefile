.PHONY: dev up down logs build test lint format \
	migrate-up migrate-down migrate-status \
	backend-shell frontend-shell rabbitmq-status clean \
	backend-build backend-test backend-lint backend-format \
	frontend-build frontend-test frontend-lint frontend-format

# Pull DB_USER/DB_PASSWORD/DB_NAME/... from .env when present so
# `make migrate-*` targets the same database the app uses.
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

## --- Local orchestration ---

dev: ## Start every service in development mode (with dev overrides)
	$(COMPOSE) up --build

up: ## Start every service in production mode
	$(COMPOSE_PROD) up --build -d

down: ## Stop and remove every service
	$(COMPOSE) down

logs: ## Tail logs from every service
	$(COMPOSE) logs -f

clean: ## Stop services and remove volumes (DESTROYS local data)
	$(COMPOSE) down -v

## --- Build ---

build: backend-build frontend-build ## Build backend and frontend binaries/artifacts

backend-build:
	cd backend && go build ./...

frontend-build:
	cd frontend && npm run build

## --- Test ---

test: backend-test frontend-test ## Run backend and frontend test suites

backend-test:
	# -p 1: several packages' tests exercise a real, shared PostgreSQL/
	# RabbitMQ (TEST_DATABASE_URL/TEST_RABBITMQ_URL) rather than mocks.
	# Running package test binaries in parallel (go test's default) lets
	# one package's live rows/messages leak into another's assertions —
	# serialize them instead.
	cd backend && go test ./... -p 1

frontend-test:
	cd frontend && npm test

## --- Lint / format ---

lint: backend-lint frontend-lint ## Lint backend and frontend

backend-lint:
	cd backend && go vet ./...

frontend-lint:
	cd frontend && npm run lint

format: backend-format frontend-format ## Format backend and frontend

backend-format:
	cd backend && go fmt ./...

frontend-format:
	cd frontend && npm run format

## --- Migrations (Goose) ---

migrate-up: ## Apply all pending migrations
	cd $(GOOSE_DIR) && goose postgres "$(DB_DSN)" up

migrate-down: ## Roll back the last migration
	cd $(GOOSE_DIR) && goose postgres "$(DB_DSN)" down

migrate-status: ## Show migration status
	cd $(GOOSE_DIR) && goose postgres "$(DB_DSN)" status

## --- Shells ---

backend-shell: ## Open a shell in the running backend-api container
	$(COMPOSE) exec backend-api sh

frontend-shell: ## Open a shell in the running frontend container
	$(COMPOSE) exec frontend sh

## --- RabbitMQ ---

rabbitmq-status: ## Show RabbitMQ node/queue status
	$(COMPOSE) exec rabbitmq rabbitmqctl status
