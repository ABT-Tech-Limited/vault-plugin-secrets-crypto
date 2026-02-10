PLUGIN_NAME := vault-plugin-crypto
VERSION := $(shell grep 'Version = ' internal/backend/backend.go | sed 's/.*"\(.*\)".*/\1/')
PLUGIN_DIR := cmd/$(PLUGIN_NAME)
BUILD_DIR := build
PLUGIN_BINARY := $(PLUGIN_NAME)-$(VERSION)

.PHONY: all build build-linux clean test fmt lint dev build-all deploy-start deploy-stop deploy-logs deploy-status

all: fmt test build-linux

# Build the plugin for Linux (Docker)
build: build-linux

# Build for Linux amd64 (for Docker)
build-linux:
	@echo "Building plugin $(VERSION) for Linux (Docker)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -o $(BUILD_DIR)/$(PLUGIN_BINARY) ./$(PLUGIN_DIR)
	@echo "Calculating SHA256..."
	@shasum -a 256 $(BUILD_DIR)/$(PLUGIN_BINARY) | cut -d ' ' -f1 > $(PLUGIN_BINARY).sha256
	@echo "SHA256: $$(cat $(PLUGIN_BINARY).sha256)"
	@echo "Build complete: $(BUILD_DIR)/$(PLUGIN_BINARY) (linux/amd64)"

# Build for current platform (macOS)
build-local:
	@echo "Building plugin $(VERSION) for local platform..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -buildvcs=false -o $(BUILD_DIR)/$(PLUGIN_BINARY)-local ./$(PLUGIN_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(PLUGIN_BINARY)-local"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -rf ./vault-plugin-crypto.*.sha256
	@go clean -cache

# Run tests
test:
	@echo "Running tests..."
	go test -v -race ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter (requires golangci-lint)
lint:
	@echo "Linting code..."
	golangci-lint run

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Build, restart container, register and enable plugin (one-shot dev reload)
VAULT_ADDR := http://127.0.0.1:8200
VAULT_TOKEN := root

dev: build-linux
	@echo "Restarting Vault container..."
	docker compose down 2>/dev/null || true
	docker compose up -d
	@echo "Waiting for Vault to be ready..."
	@for i in $$(seq 1 30); do \
		if curl -sf $(VAULT_ADDR)/v1/sys/health > /dev/null 2>&1; then \
			echo "Vault is ready."; \
			break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "Error: Vault failed to start within 30s"; \
			exit 1; \
		fi; \
		sleep 1; \
	done
	@echo "Registering plugin $(VERSION)..."
	@SHA256=$$(shasum -a 256 $(BUILD_DIR)/$(PLUGIN_BINARY) | cut -d ' ' -f1) && \
	curl -sf -X POST \
		-H "X-Vault-Token: $(VAULT_TOKEN)" \
		-d "{\"sha256\":\"$$SHA256\",\"command\":\"$(PLUGIN_BINARY)\",\"version\":\"$(VERSION)\"}" \
		$(VAULT_ADDR)/v1/sys/plugins/catalog/secret/$(PLUGIN_NAME) > /dev/null
	@echo "Enabling plugin at /crypto..."
	@curl -sf -X POST \
		-H "X-Vault-Token: $(VAULT_TOKEN)" \
		-d '{"type":"$(PLUGIN_NAME)","plugin_version":"$(VERSION)"}' \
		$(VAULT_ADDR)/v1/sys/mounts/crypto > /dev/null
	@echo ""
	@echo "=== Plugin ready ==="
	@echo "  VAULT_ADDR:  $(VAULT_ADDR)"
	@echo "  VAULT_TOKEN: $(VAULT_TOKEN)"
	@echo "  Mount path:  /crypto"
	@echo "  Version:     $(VERSION)"

# Build for multiple platforms
build-all:
	@echo "Building $(VERSION) for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -o $(BUILD_DIR)/$(PLUGIN_BINARY)-linux-amd64 ./$(PLUGIN_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -buildvcs=false -o $(BUILD_DIR)/$(PLUGIN_BINARY)-linux-arm64 ./$(PLUGIN_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -o $(BUILD_DIR)/$(PLUGIN_BINARY)-darwin-amd64 ./$(PLUGIN_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -buildvcs=false -o $(BUILD_DIR)/$(PLUGIN_BINARY)-darwin-arm64 ./$(PLUGIN_DIR)
	@echo "Multi-platform build complete"

# Quick test - create a key and sign
quicktest:
	@echo "Quick test: creating key and signing..."
	@echo "Creating secp256k1 key..."
	@curl -s -X POST -H "X-Vault-Token: root" \
		-d '{"curve":"secp256k1","name":"test-key"}' \
		http://127.0.0.1:8200/v1/crypto/keys | jq .
	@echo ""
	@echo "Listing keys..."
	@curl -s -X LIST -H "X-Vault-Token: root" \
		http://127.0.0.1:8200/v1/crypto/keys | jq .

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build for Linux/Docker (default)"
	@echo "  build-linux    - Build for Linux amd64 (Docker)"
	@echo "  build-local    - Build for current platform (macOS)"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  fmt            - Format code"
	@echo "  lint           - Run linter"
	@echo "  deps           - Download dependencies"
	@echo "  dev     		- Build, restart container, register & enable plugin"
	@echo "  quicktest      - Quick test with curl"
	@echo "  deploy-start   - Start production Vault"
	@echo "  deploy-stop    - Stop production Vault"
	@echo "  deploy-logs    - Follow production Vault logs"
	@echo "  deploy-status  - Show production Vault status"
	@echo "  help           - Show this help"

# Production deployment
deploy-start:
	cd deploy && docker compose -f docker-compose.prod.yml --env-file .env up -d

deploy-stop:
	cd deploy && docker compose -f docker-compose.prod.yml --env-file .env down

deploy-logs:
	cd deploy && docker compose -f docker-compose.prod.yml logs -f

deploy-status:
	cd deploy && ./setup.sh status
