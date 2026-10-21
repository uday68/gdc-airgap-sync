# GDC Air-Gap Sync - Cryptographic Provenance & Interview Study Guide

> **Target Role:** Google Distributed Cloud (GDC) – Virtual Machine Infrastructure & Security Team  
> **Repository:** `github.com/uday68/gdc-airgap-sync`  
> **Key Technologies:** Go (Golang), Asymmetric Cryptography (Ed25519), Software Supply Chain (SLSA / SPDX SBOM), Air-Gapped Data Diode Ingestion, Atomic File Replacement.

---

## 1. Problem Statement: The Air-Gap Boundary & Trust Dilemma

In high-security disconnected infrastructure (defense agencies, sovereign cloud, air-gapped data centers), external internet access is prohibited. To update operating system images, hypervisor templates, and application workloads, release bundles must be transferred across the air gap via offline removable media or unidirectional hardware data diodes.

### The Threat Model
1. **Malicious Tampering in Transit:** An adversary alters an OS image or rootfs during transit to inject backdoors or rootkits.
2. **Untrusted Extraction Contamination:** If the ingestion tool decompresses and writes untrusted files to disk *before* checking the digital signature, an attacker can execute decompression bombs or place unauthorized payloads before signature rejection.
3. **Archive Traversal ("Tar Slip"):** Archives containing relative paths (`../`), backslashes (`..\`), or reserved device names (`CON`, `NUL`) could escape the target directory or corrupt host operating system files.
4. **Key Compromise & Revocation:** In an offline environment without OCSP or CRL network endpoints, the system requires an explicit offline trust store to rotate keys, enforce validity windows, and revoke compromised keys.

---

## 2. Key Architecture & Engineering Principles

### 1. Verification-Before-Extraction
* Traditional tar ingestion tools extract entries to disk and then verify signatures at the end. If an invalid or malicious package is provided, hostile bytes are already on disk.
* In `gdc-airgap-sync`, `manifest.yaml` is guaranteed to be the first entry in the archive. The ingestion pipeline parses the manifest into memory under strict size bounds (`io.LimitReader`), verifies the Ed25519 signature against the offline trust store, and **only then** begins extracting artifact payloads.
* If signature verification fails, the pipeline aborts immediately with zero disk contamination.

### 2. Ed25519 Asymmetric Cryptography & Offline Trust Store
* **Why Ed25519?** Ed25519 offers 128-bit security level with compact 32-byte public keys and 64-byte signatures, fast constant-time verification, and resistance to side-channel and entropy failure attacks.
* **Offline Trust Store (`pkg/truststore`):**
  * Tracks trusted keys by deterministic public key SHA-256 fingerprint (`KeyID`).
  * Enforces signer identity binding, authorization scope (`all`, `os-images`), and validity windows (`NotBefore`, `NotAfter`).
  * Supports offline revocation: revoked keys are immediately rejected with an explicit audit reason.

### 3. Truthful Provenance & Cryptographic SBOM Binding
* No hardcoded or fabricated release origins. Manifests capture genuine build pipeline metadata, release identifiers, and cryptographically bind the SHA-256 digest of attached SPDX 2.3 or CycloneDX SBOM files.
* Tampering with either the artifact image or the SBOM document produces an instant signature or digest mismatch error.

### 4. Reproducible Bundle Creation
* Builds byte-for-byte identical archives from the same inputs by normalizing:
  * Tar header timestamps (`ModTime` set to source modtime or fixed epoch).
  * Tar header ownership (`Uid: 0, Gid: 0, Uname: "", Gname: ""`).
  * Permissions (`0644`).
  * Forward slash normalization (`artifacts/<clean-filename>`) across all platforms.
  * Gzip OS header flag (`255` for unknown/neutral OS).

### 5. Streaming Integrity ($O(1)$ Constant Memory Overhead)
* Disk images can be 50 GB.
* `io.MultiWriter` pipes the incoming tar decompression stream simultaneously into the staged temporary file and `sha256.New()`.
* The entire disk is verified in a single streaming pass without buffering gigabytes of data into RAM.
* Protected against decompression bombs via bounded readers: `io.LimitReader(tarReader, art.SizeBytes + 1)`.

### 6. Transactional Promotion & Platform-Aware Atomic Replacement
* Staged files are extracted to private temporary locations.
* Only after all declared artifacts pass digest verification are they promoted to the `gdc-vm-operator` images directory and catalog index (`catalog.yaml`).
* On Windows, file replacements are subject to transient locks (antivirus scanners, indexers); `pathutil.SafeReplaceFile` implements atomic rename with bounded retry and exponential backoff.

---

## 3. Google Interview Q&A

**Q: How do you verify the integrity and origin of software artifacts in an air-gapped environment?**  
*Answer:*  
> *"In `gdc-airgap-sync`, I implemented a zero-trust cryptographic provenance model inspired by Sigstore and in-toto. In the connected build environment, release artifacts and their SPDX SBOM are packaged into a reproducible archive and signed with an Ed25519 private key. Inside the disconnected cluster, an offline trust store manages authorized key fingerprints, validity windows, and revocations. The ingestion pipeline strictly enforces verification-before-extraction: `manifest.yaml` is read and cryptographically verified before any artifact bytes are extracted to disk."*

**Q: What is the risk of extracting archive entries before verifying the digital signature?**  
*Answer:*  
> *"Extracting before verification violates defense-in-depth. If an attacker supplies an archive with hostile content or a decompression bomb, untrusted files get written to the host filesystem before signature failure triggers. In `gdc-airgap-sync`, we read the manifest first, verify the Ed25519 signature over canonical serialized bytes, and reject invalid archives before a single temporary file or artifact byte is written to storage."*

**Q: How do you defend against path traversal and 'Tar Slip' vulnerabilities in Go?**  
*Answer:*  
> *"Naive string concatenation with `filepath.Join` is vulnerable to path traversal if the archive entry contains relative paths (`../`) or absolute path prefixes. We enforce three defense layers: first, strict allowlisting of permitted archive entries (`manifest.yaml`, `sbom.json`, `artifacts/<filename>`); second, `pathutil.ValidateFilename` rejects any path containing slashes, backslashes, colons, null bytes, or Windows reserved device names (`CON`, `NUL`); and third, `pathutil.SafeJoin` computes `filepath.Rel` and asserts the resulting path remains strictly within the target directory."*

**Q: Why is streaming hashing important when dealing with virtual machine images?**  
*Answer:*  
> *"Virtual machine images are often tens or hundreds of gigabytes. Loading them into RAM causes Out-Of-Memory (OOM) kills. By piping extraction streams through Go's `io.MultiWriter` directly into `sha256.New()`, we verify the cryptographic checksum in a single streaming pass with $O(1)$ constant memory overhead, while `io.LimitReader` guarantees the payload never exceeds declared byte limits."*
