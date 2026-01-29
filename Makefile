PLUGIN_NAME := vault-plugin-crypto
VERSION := $(shell grep 'Version = ' internal/backend/backend.go | sed 's/.*"\(.*\)".*/\1/')
PLUGIN_DIR := cmd/$(PLUGIN_NAME)
BUILD_DIR := build
PLUGIN_BINARY := $(PLUGIN_NAME)-$(VERSION)

.PHONY: all build build-linux clean test fmt lint dev register enable disable build-all

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

# Start Vault in dev mode with plugin directory
dev: build
	@echo "Starting Vault in dev mode..."
	@echo "Run the following commands in another terminal:"
	@echo "  export VAULT_ADDR='http://127.0.0.1:8200'"
	@echo "  export VAULT_TOKEN='root'"
	@echo "  vault secrets enable -path=crypto -plugin-name=$(PLUGIN_NAME) plugin"
	@echo ""
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=$$(pwd)/$(BUILD_DIR)

# Register plugin (production environment)
register:
	@echo "Registering plugin $(VERSION)..."
	@SHA256=$$(cat $(PLUGIN_BINARY).sha256) && \
	vault plugin register -sha256=$$SHA256 -version=$(VERSION) secret $(PLUGIN_NAME)

# Enable plugin at /crypto path
enable:
	@echo "Enabling plugin at path 'crypto'..."
	vault secrets enable -path=crypto -plugin-name=$(PLUGIN_NAME) plugin

# Disable plugin
disable:
	@echo "Disabling plugin..."
	vault secrets disable crypto

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
	@echo "  build        - Build for Linux/Docker (default)"
	@echo "  build-linux  - Build for Linux amd64 (Docker)"
	@echo "  build-local  - Build for current platform (macOS)"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  fmt          - Format code"
	@echo "  lint         - Run linter"
	@echo "  deps         - Download dependencies"
	@echo "  dev          - Start Vault in dev mode (requires local vault)"
	@echo "  quicktest    - Quick test with curl"
	@echo "  help         - Show this help"
