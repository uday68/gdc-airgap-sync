# Makefile for GDC Air-Gapped Artifact Synchronization CLI

BINARY := bin/airgap-sync

.PHONY: all build test lint clean

all: build test

build:
	@echo "==> Building airgap-sync CLI..."
	go build -o $(BINARY) ./cmd/airgap-sync

test:
	@echo "==> Running test suite..."
	go test -v ./...

lint:
	@echo "==> Running static analysis..."
	go vet ./...

clean:
	@echo "==> Cleaning generated binaries and artifacts..."
	rm -rf bin/ dist/ keys/
