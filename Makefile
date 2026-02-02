.PHONY: all build test clean install lint fmt vet

BINARY_NAME=secrets
BUILD_DIR=./build
CMD_DIR=./cmd/secrets

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Build flags
LDFLAGS=-ldflags "-s -w"

all: test build

build:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

build-debug:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

test:
	$(GOTEST) -v -race ./...

test-short:
	$(GOTEST) -short ./...

test-cover:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

integration:
	$(GOTEST) -v -tags=integration ./...

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

deps:
	$(GOMOD) download
	$(GOMOD) tidy

fmt:
	$(GOFMT) -s -w .

vet:
	$(GOVET) ./...

lint: fmt vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

# Development helpers
dev-setup:
	$(GOMOD) download
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

# Initialize a test store
init-test: build
	$(BUILD_DIR)/$(BINARY_NAME) init

# Quick check before commit
check: fmt vet test-short
