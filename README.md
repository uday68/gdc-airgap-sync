# GDC Air-Gap Sync (`gdc-airgap-sync`)

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Security](https://img.shields.io/badge/Cryptography-Ed25519-red)]()
[![Supply Chain](https://img.shields.io/badge/Supply%20Chain-SPDX%20SBOM-blue)]()
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-brightgreen)]()

A secure **Cryptographic Provenance, Software Supply-Chain & Offline Ingestion CLI in Go**, designed to bridge the air-gap boundary for **Google Distributed Cloud (GDC)**.

Companion project to [**`gdc-vm-operator`**](https://github.com/uday68/gdc-vm-operator).

---

## 1. Architecture: Crossing the Air Gap

```mermaid
flowchart LR
    subgraph ConnectedZone["1. Connected Zone (Build & Release)"]
        RawImage["Raw VM Disk (ubuntu-22.04.qcow2)"] --> Bundler["airgap-sync bundle"]
        PrivateKey["Release Private Key (Ed25519)"] --> Bundler
        Bundler --> Package["Signed Air-Gap Bundle (.tar.gz)"]
    end

    Package -->|Physical Transfer Across Air Gap| IngestTool

    subgraph AirGappedZone["2. Air-Gapped GDC Zone (Zero Egress)"]
        IngestTool["airgap-sync ingest"]
        PublicKey["Trusted Public Key (Ed25519)"] --> IngestTool
        IngestTool -->|Verify Digital Signature & Digest| GDCRegistry["GDC Local Registry (gdc-vm-operator)"]
    end
```

---

## 2. Features

* **Asymmetric Digital Signatures:** Generates and verifies cryptographic signatures with modern **Ed25519** public-key cryptography.
* **SPDX Software Bill of Materials (SBOM):** Embeds package inventories for supply-chain compliance and vulnerability audits.
* **Streaming Integrity Checks:** Computes SHA-256 digests via `io.MultiWriter` in $O(1)$ constant memory during decompression.
* **Zero-Trust Ingestion:** Rejects any tampered or unverified artifacts before promoting them to `gdc-vm-operator`'s local catalog.

---

## 3. Quickstart

### Step 1: Generate Signing Keypair
```bash
go build -o bin/airgap-sync.exe ./cmd/airgap-sync
.\bin\airgap-sync.exe keygen --out-dir ./keys
```

### Step 2: Package & Sign an OS Image (Connected Zone)
```bash
.\bin\airgap-sync.exe bundle \
  --name rhel-9 \
  --file rhel-9.qcow2 \
  --key ./keys/release-private.pem \
  --out ./dist/rhel-9.bundle.tar.gz
```

### Step 3: Inspect the Release Bundle
```bash
.\bin\airgap-sync.exe inspect --bundle ./dist/rhel-9.bundle.tar.gz
```

### Step 4: Verify Digital Signature
```bash
.\bin\airgap-sync.exe verify \
  --bundle ./dist/rhel-9.bundle.tar.gz \
  --pubkey ./keys/release-public.pem
```

### Step 5: Ingest into GDC Virtual Machine Operator
```bash
.\bin\airgap-sync.exe ingest \
  --bundle ./dist/rhel-9.bundle.tar.gz \
  --pubkey ./keys/release-public.pem \
  --registry-dir ../gdc-vm-operator/data/registry
```

---

## 4. Test Suite

```bash
go test -v ./...
```
* **Coverage:** Keypair serialization/deserialization, signing, verification, tamper-detection, tarball bundling, and end-to-end promotion into the GDC operator registry.

For technical deep dive and Google interview talking points, consult the [Interview Study Guide](docs/INTERVIEW_STUDY_GUIDE.md).
