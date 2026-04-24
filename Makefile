# Sigil Auth — Docker Compose Makefile
#
# Targets:
#   make up      Start stack (development mode)
#   make down    Stop and remove stack
#   make test    Start stack with test overrides
#   make prod    Start stack with production overrides
#   make logs    Tail logs from all services
#   make seed    Seed database with test data
#   make clean   Remove all volumes (WARNING: data loss)
#   make health  Check service health status

.PHONY: up down test prod logs seed clean health ps restart

# Default environment
ENV ?= dev

# Docker Compose base command
COMPOSE := docker-compose
COMPOSE_FILES := -f docker-compose.yml

# Test environment
ifeq ($(ENV),test)
	COMPOSE_FILES += -f docker-compose.test.yml
endif

# Production environment
ifeq ($(ENV),prod)
	COMPOSE_FILES += -f docker-compose.prod.yml
endif

## up: Start stack (default: development mode)
up:
	@echo "Starting Sigil stack..."
	$(COMPOSE) $(COMPOSE_FILES) up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@$(MAKE) health

## down: Stop and remove stack
down:
	@echo "Stopping Sigil stack..."
	$(COMPOSE) $(COMPOSE_FILES) down

## test: Start stack with test overrides (mocked APNs/FCM)
test:
	@echo "Starting Sigil stack in TEST mode..."
	$(COMPOSE) -f docker-compose.yml -f docker-compose.test.yml up -d
	@sleep 5
	@$(MAKE) health

## prod: Start stack with production overrides
prod:
	@echo "Starting Sigil stack in PRODUCTION mode..."
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml up -d
	@sleep 10
	@$(MAKE) health

## logs: Tail logs from all services
logs:
	$(COMPOSE) $(COMPOSE_FILES) logs -f

## logs-sigil: Tail logs from sigil service only
logs-sigil:
	$(COMPOSE) $(COMPOSE_FILES) logs -f sigil

## logs-relay: Tail logs from relay service only
logs-relay:
	$(COMPOSE) $(COMPOSE_FILES) logs -f relay

## ps: Show running containers
ps:
	$(COMPOSE) $(COMPOSE_FILES) ps

## restart: Restart all services
restart:
	@echo "Restarting Sigil stack..."
	$(COMPOSE) $(COMPOSE_FILES) restart
	@sleep 5
	@$(MAKE) health

## health: Check service health status
health:
	@echo "\nChecking service health..."
	@echo "Postgres:"
	@docker exec sigil-postgres pg_isready -U relay || echo "  ❌ PostgreSQL unhealthy"
	@echo "\nRelay:"
	@curl -s -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:8080/health || echo "  ❌ Relay unhealthy"
	@echo "\nSigil:"
	@curl -s -o /dev/null -w "  HTTP %{http_code}\n" -k https://localhost:8443/health || echo "  ❌ Sigil unhealthy"
	@echo ""

## seed: Seed database with test data (requires test-harness)
seed:
	@echo "Seeding database with test data..."
	@if [ "$(ENV)" != "test" ]; then \
		echo "Error: seed target requires test environment"; \
		echo "Run: make test seed"; \
		exit 1; \
	fi
	@echo "Creating test devices..."
	@docker exec sigil-test-harness /app/harness seed --devices 10

## clean: Remove all volumes (WARNING: data loss)
clean:
	@echo "⚠️  WARNING: This will delete ALL data (postgres + sigil volumes)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Stopping stack and removing volumes..."; \
		$(COMPOSE) $(COMPOSE_FILES) down -v; \
		docker volume rm sigil-postgres-data sigil-server-data || true; \
		echo "Volumes removed."; \
	else \
		echo "Cancelled."; \
	fi

## build: Build Docker images
build:
	@echo "Building Docker images..."
	$(COMPOSE) $(COMPOSE_FILES) build

## rebuild: Rebuild images from scratch (no cache)
rebuild:
	@echo "Rebuilding Docker images from scratch..."
	$(COMPOSE) $(COMPOSE_FILES) build --no-cache

## observability: Start stack with observability (Prometheus, Grafana, Loki, etc.)
observability:
	@echo "Starting Sigil stack with observability..."
	$(COMPOSE) -f docker-compose.yml -f deploy/observability/docker-compose.observability.yml up -d
	@sleep 10
	@$(MAKE) health-obs

## health-obs: Check observability stack health
health-obs:
	@echo "\nChecking observability stack health..."
	@echo "Prometheus:"
	@curl -s -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:9090/-/healthy || echo "  ❌ Prometheus unhealthy"
	@echo "\nGrafana:"
	@curl -s -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:3000/api/health || echo "  ❌ Grafana unhealthy"
	@echo "\nLoki:"
	@curl -s -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:3100/ready || echo "  ❌ Loki unhealthy"
	@echo "\nTempo:"
	@curl -s -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:3200/ready || echo "  ❌ Tempo unhealthy"
	@echo ""
	@echo "Access URLs:"
	@echo "  Grafana:    http://localhost:3000"
	@echo "  Prometheus: http://localhost:9090"

## down-obs: Stop observability stack
down-obs:
	@echo "Stopping observability stack..."
	$(COMPOSE) -f docker-compose.yml -f deploy/observability/docker-compose.observability.yml down

## help: Show this help message
help:
	@echo "Sigil Auth — Docker Compose Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

.DEFAULT_GOAL := help
