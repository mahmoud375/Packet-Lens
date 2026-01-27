# PacketLens Makefile
# Build automation for protobuf compilation and development tasks

.PHONY: all proto proto-go proto-python install-proto-tools clean help

# Default target
all: proto

# ============================================================================
# Protobuf Compilation
# ============================================================================

# Generate both Go and Python stubs
proto: proto-go proto-python
	@echo "✓ All protobuf stubs generated successfully"

# Generate Go protobuf stubs
proto-go:
	@echo "Generating Go protobuf stubs..."
	@mkdir -p gen/go
	protoc \
		--proto_path=proto \
		--go_out=gen/go \
		--go_opt=paths=source_relative \
		--go-grpc_out=gen/go \
		--go-grpc_opt=paths=source_relative \
		proto/packetlens.proto
	@echo "✓ Go stubs generated in gen/go/"

# Generate Python protobuf stubs
proto-python:
	@echo "Generating Python protobuf stubs..."
	@mkdir -p services/inference/proto
	python -m grpc_tools.protoc \
		--proto_path=proto \
		--python_out=services/inference/proto \
		--pyi_out=services/inference/proto \
		--grpc_python_out=services/inference/proto \
		proto/packetlens.proto
	@touch services/inference/proto/__init__.py
	@echo "✓ Python stubs generated in services/inference/proto/"

# ============================================================================
# Tool Installation
# ============================================================================

# Install protoc plugins for Go and Python
install-proto-tools:
	@echo "Installing Go protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Installing Python grpcio-tools..."
	pip install grpcio grpcio-tools
	@echo "✓ All protoc plugins installed"
	@echo ""
	@echo "NOTE: Ensure protoc (Protocol Buffer Compiler) is installed:"
	@echo "  Ubuntu/Debian: sudo apt install protobuf-compiler"
	@echo "  macOS: brew install protobuf"

# ============================================================================
# Cleanup
# ============================================================================

clean:
	@echo "Cleaning generated files..."
	rm -rf gen/go/*.go
	rm -rf services/inference/proto/*.py
	rm -rf services/inference/proto/*.pyi
	@echo "✓ Generated files cleaned"

# ============================================================================
# Help
# ============================================================================

help:
	@echo "PacketLens Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  proto              Generate all protobuf stubs (Go + Python)"
	@echo "  proto-go           Generate Go protobuf stubs only"
	@echo "  proto-python       Generate Python protobuf stubs only"
	@echo "  install-proto-tools Install protoc plugins for Go and Python"
	@echo "  clean              Remove generated protobuf files"
	@echo "  help               Show this help message"
