# Makefile for GDC Air-Gapped Artifact Synchronization CLI

BINARY := bin/airgap-sync

.PHONY: all build test test-race lint clean fuzz e2e

all: build lint test

build:
	@echo "==> Building airgap-sync CLI..."
	go build -o $(BINARY) ./cmd/airgap-sync

test:
	@echo "==> Running unit test suite..."
	go test -v ./...

test-race:
	@echo "==> Running test suite with race detector..."
	go test -race -v ./...

lint:
	@echo "==> Running static analysis..."
	go vet ./...

fuzz:
	@echo "==> Running fuzz testing..."
	go test -fuzz=FuzzParseManifest -fuzztime=5s ./pkg/manifest
	go test -fuzz=FuzzIngestArchive -fuzztime=5s ./pkg/ingest

e2e:
	@echo "==> Running cross-repo end-to-end integration test..."
	go test -v ./test/e2e

clean:
	@echo "==> Cleaning generated binaries and artifacts..."
	rm -rf bin/ dist/ keys/
