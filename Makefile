.PHONY: build clean install test build-linux package-linux clean-packages

BINARY_NAME=pam_oidc_auth

BUILD_DIR=dist

INSTALL_DIR=/usr/local/bin

# Default architecture (can be overridden)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

GIT_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION := $(GIT_TAG)-$(GIT_COMMIT)

# Build flags (embed version to builds)
LDFLAGS := -X main.Version=$(VERSION)

# Common target architectures
LINUX_ARCHS=amd64 arm64 arm

# Build for current platform (mostly development)
build:
	@mkdir -p $(BUILD_DIR)
	@echo "Building $(BINARY_NAME) for $(GOOS)/$(GOARCH) with version $(VERSION)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH) .
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)"

# Builds linux binaries for all common architectures
build-linux:
	@mkdir -p $(BUILD_DIR)
	@for arch in $(LINUX_ARCHS); do \
		echo "Building $(BINARY_NAME) for linux/$$arch with version $(VERSION)..."; \
		GOOS=linux GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-$$arch .; \
		echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-linux-$$arch"; \
	done

# Build and package for all common linux architectures
package-linux: build-linux
	@echo "Packaging Linux binaries with git version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)/packages
	@for arch in $(LINUX_ARCHS); do \
		binary="$(BUILD_DIR)/$(BINARY_NAME)-linux-$$arch"; \
		if [ -f "$$binary" ]; then \
			package_name="$(BINARY_NAME)-linux-$$arch-$(VERSION)"; \
			echo "Creating package: $$package_name.tar.gz"; \
			mkdir -p $(BUILD_DIR)/packages/$$package_name; \
			cp $$binary $(BUILD_DIR)/packages/$$package_name/; \
			cp install.sh $(BUILD_DIR)/packages/$$package_name/; \
			cp INSTALLATION.md $(BUILD_DIR)/packages/$$package_name/; \
			cp config.dist* $(BUILD_DIR)/packages/$$package_name/; \
			cp ssh_banner.txt $(BUILD_DIR)/packages/$$package_name/; \
			cp -r pam.d $(BUILD_DIR)/packages/$$package_name/; \
			cd $(BUILD_DIR)/packages && tar -czf $$package_name.tar.gz $$package_name && cd -;  \
			rm -rf $(BUILD_DIR)/packages/$$package_name; \
		fi \
	done
	@echo "Linux packages created in $(BUILD_DIR)/packages/"
	@ls -la $(BUILD_DIR)/packages/


clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@go clean

# Clean only packages
clean-packages:
	@echo "Cleaning packages..."
	@rm -rf $(BUILD_DIR)/packages


test:
	@echo "Running tests..."
	@go test -v ./...

# Development helpers
dev-build: 
	@mkdir -p $(BUILD_DIR)
	@go build -race -o $(BUILD_DIR)/$(BINARY_NAME)-dev .

fmt:
	@go fmt ./...

vet:
	@go vet ./...

mod-tidy:
	@go mod tidy

# Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Building:"
	@echo "  build           - Build for current platform ($(shell go env GOOS)/$(shell go env GOARCH))"
	@echo "  build-linux     - Build for all Linux architectures"
	@echo "  dev-build       - Build with race detection for development"
	@echo ""
	@echo "Packaging:"
	@echo "  package-all     - Package all built binaries separately (requires build-all)"
	@echo "  package-linux   - Package only Linux binaries (requires build-linux)"
	@echo "  package-binary  - Package specific binary (Usage: make package-binary BINARY=bin/binary-name)"
	@echo ""
	@echo "Development:"
	@echo "  test            - Run tests"
	@echo "  fmt             - Format code"
	@echo "  vet             - Run go vet"
	@echo "  mod-tidy        - Tidy module dependencies"
	@echo ""
	@echo "Cleaning:"
	@echo "  clean           - Clean all build artifacts"
	@echo "  clean-packages  - Clean only package artifacts"
	@echo ""
	@echo "Information:"
	@echo "  list-archs      - List all supported architectures"
	@echo ""
	@echo "Version info: $(VERSION)"
	@echo ""
	@echo "Examples:"
	@echo "  make build GOOS=linux GOARCH=amd64"
	@echo "  make build-linux && make package-linux"
	@echo "  make build-all && make package-all"
	@echo "  make package-binary BINARY=bin/pam_oidc_auth-linux-amd64"