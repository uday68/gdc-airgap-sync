# GDC Air-Gap Sync - Cryptographic Provenance & Interview Study Guide

> **Target Role:** Google Distributed Cloud (GDC) – Virtual Machine Infrastructure & Security Team  
> **Repository:** `github.com/uday68/gdc-airgap-sync`  
> **Key Technologies:** Go (Golang), Asymmetric Cryptography (Ed25519), Software Supply Chain (SLSA / SPDX SBOM), Air-Gapped Data Diode Ingestion.

---

## 1. Problem Statement: The "Stuxnet" Air-Gap Dilemma
In high-security disconnected infrastructure (defense agencies, sovereign cloud, nuclear power stations), external internet connections are strictly prohibited. To update operating system images, software bundles must be carried across the air-gap boundary via physical offline media (or hardware data diodes).

If an adversary alters disk images in transit to inject backdoors or rootkits, unverified ingestion compromises the entire secure facility.

`gdc-airgap-sync` solves this by establishing **end-to-end cryptographic provenance**:
1. **Connected Zone Packaging:** Release engineers sign packages with an Ed25519 private key and embed an SPDX SBOM.
2. **Air-Gapped Ingestion:** The ingestion engine re-verifies the digital signature and SHA-256 digests against a trusted public key before promoting images into the local registry.

---

## 2. Key Go & Cryptographic Concepts

### 1. Ed25519 Asymmetric Cryptography (`crypto/ed25519`)
* **Why Ed25519 instead of RSA-2048 or RSA-4096?**
  * Ed25519 (Edwards-curve Digital Signature Algorithm) offers 128-bit security level with much smaller keys (32-byte public key) and signatures (64 bytes).
  * It is immune to several side-channel attacks and does not require a cryptographically secure random number generator during signing (preventing catastrophic entropy failure attacks like Sony PS3 ECDSA).
* **PKCS#8 & PKIX PEM Encoding (`encoding/pem`, `crypto/x509`):**
  * Standardized export and import of private (`x509.MarshalPKCS8PrivateKey`) and public (`x509.MarshalPKIXPublicKey`) keys.

### 2. Canonical Manifest Serialization
* **Why Canonical Serialization?**
  * The manifest struct includes `Signature: string`.
  * If you sign the JSON/YAML including the signature field, computing the hash is impossible (circular dependency).
  * `CanonicalBytes()` sets `Signature = ""` and serializes the data deterministically so the recipient verifies the exact bytes that were signed.

### 3. Streaming Verification ($O(1)$ Memory)
* Disk images can be 50 GB.
* During extraction, `io.MultiWriter` streams bytes into both the temporary file and the `sha256.New()` hasher concurrently. The entire 50 GB disk is checked with zero memory buffering.

---

## 3. Google Interview Q&A

**Q: How do you verify the integrity and origin of software artifacts in an air-gapped system?**  
*Answer:*  
> *"In `gdc-airgap-sync`, I implemented cryptographic provenance modeled after Sigstore and Cosign. In the connected build environment, release artifacts and their SPDX SBOM are packaged into an archive and signed with an Ed25519 private key. Inside the disconnected cluster, the ingestion tool verifies the Ed25519 digital signature against the enterprise public key and verifies streaming SHA-256 digests before permitting the image into the local virtualization catalog."*

**Q: Why is streaming hashing important when handling VM images?**  
*Answer:*  
> *"Loading multi-gigabyte disk images into memory with standard read utilities causes Out-Of-Memory (OOM) failures in containerized operators. By piping extraction streams through Go's `io.MultiWriter` directly into `sha256.New()`, we compute the cryptographic digest in a single streaming pass with $O(1)$ constant memory overhead."*
