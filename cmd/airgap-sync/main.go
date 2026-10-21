package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/bundler"
	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/ingest"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"github.com/uday68/gdc-airgap-sync/pkg/truststore"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "keygen":
		cmdKeygen(args)
	case "bundle":
		cmdBundle(args)
	case "inspect":
		cmdInspect(args)
	case "verify":
		cmdVerify(args)
	case "ingest":
		cmdIngest(args)
	case "truststore":
		cmdTrustStore(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`GDC Air-Gapped Secure Artifact Ingestion Tool (airgap-sync)

Usage:
  airgap-sync <command> [flags]

Available Commands:
  keygen                   Generate Ed25519 cryptographic release keypair (PEM)
  bundle                   Package and sign raw VM disk images with SBOM into .tar.gz
  inspect                  Inspect bundle manifest, artifacts, and SBOM without ingesting
  verify                   Validate cryptographic signature against public key or trust store
  ingest                   Verify and import release bundle into GDC local registry
  truststore               Manage offline trusted release keys (init, add, list, revoke)

Run 'airgap-sync <command> --help' for details on each subcommand.
`)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("out-dir", "keys", "Output directory for PEM keys")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Printf("Failed creating output directory: %v\n", err)
		os.Exit(1)
	}

	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		fmt.Printf("Key generation failed: %v\n", err)
		os.Exit(1)
	}

	privPath := filepath.Join(*outDir, "release-private.pem")
	pubPath := filepath.Join(*outDir, "release-public.pem")

	if err := crypto.SavePEM(priv, pub, privPath, pubPath); err != nil {
		fmt.Printf("Failed saving PEM keys: %v\n", err)
		os.Exit(1)
	}

	fingerprint := crypto.PublicKeyFingerprint(pub)
	fmt.Println("[KEYGEN] Ed25519 signing keypair generated successfully:")
	fmt.Printf("         Private Key: %s (Keep secure in Connected Zone)\n", privPath)
	fmt.Printf("         Public Key:  %s (Deploy to Air-Gapped GDC clusters)\n", pubPath)
	fmt.Printf("         Key ID:      %s\n", fingerprint)
}

func cmdBundle(args []string) {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	name := fs.String("name", "", "Artifact image name (e.g. ubuntu-22.04)")
	file := fs.String("file", "", "Path to source disk image file")
	key := fs.String("key", "", "Path to release private key PEM")
	out := fs.String("out", "", "Output path for signed bundle (.tar.gz)")
	osFamily := fs.String("os", "linux", "OS Family (linux, windows)")
	desc := fs.String("desc", "GDC Verified Gold Image", "Image description")
	signer := fs.String("signer", "", "Signer identity (e.g. releng@example.com)")
	origin := fs.String("origin", "developer-build", "Build pipeline origin")
	releaseID := fs.String("release-id", "", "Release tag or build ID")
	sbomPath := fs.String("sbom", "", "Path to SPDX/CycloneDX SBOM file (optional)")
	demoFixture := fs.Bool("demo-fixture", false, "Generate synthetic demo SBOM fixture")
	_ = fs.Parse(args)

	if *name == "" || *file == "" || *key == "" || *out == "" || *signer == "" {
		fmt.Println("Error: --name, --file, --key, --signer, and --out flags are all required")
		fs.Usage()
		os.Exit(1)
	}

	privKey, err := crypto.LoadPrivateKeyPEM(*key)
	if err != nil {
		fmt.Printf("Failed loading private key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[BUNDLE] Packaging and signing '%s' from '%s'...\n", *name, *file)
	mf, err := bundler.CreateBundle(bundler.BundleOptions{
		Name:           *name,
		SourceFilePath: *file,
		OSFamily:       *osFamily,
		Description:    *desc,
		SignerIdentity: *signer,
		PrivateKey:     privKey,
		OutputPath:     *out,
		Origin:         *origin,
		ReleaseID:      *releaseID,
		SBOMPath:       *sbomPath,
		DemoFixture:    *demoFixture,
	})
	if err != nil {
		fmt.Printf("Bundle creation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[SUCCESS] Air-gapped release bundle created:")
	fmt.Printf("          Bundle ID:    %s\n", mf.BundleID)
	fmt.Printf("          Key ID:       %s\n", mf.KeyID)
	fmt.Printf("          Signer:       %s\n", mf.SignerIdentity)
	fmt.Printf("          Origin:       %s\n", mf.Origin)
	fmt.Printf("          Signature:    %s\n", mf.Signature)
	fmt.Printf("          Destination:  %s\n", *out)
}

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to .tar.gz bundle archive")
	_ = fs.Parse(args)

	if *bundlePath == "" {
		fmt.Println("Error: --bundle flag is required")
		os.Exit(1)
	}

	mf, err := readManifestFromBundle(*bundlePath)
	if err != nil {
		fmt.Printf("Failed inspecting bundle: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Bundle ID:       %s\n", mf.BundleID)
	fmt.Printf("API Version:     %s\n", mf.APIVersion)
	fmt.Printf("Created:         %s\n", mf.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Origin:          %s\n", mf.Origin)
	if mf.ReleaseID != "" {
		fmt.Printf("Release ID:      %s\n", mf.ReleaseID)
	}
	fmt.Printf("Signer Identity: %s\n", mf.SignerIdentity)
	if mf.KeyID != "" {
		fmt.Printf("Key ID:          %s\n", mf.KeyID)
	}
	fmt.Printf("Signature:       %s\n", mf.Signature)

	fmt.Println("\nArtifacts:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tFILENAME\tOS\tSIZE (BYTES)\tSHA256 CHECKSUM")
	for _, a := range mf.Artifacts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", a.Name, a.Filename, a.OSFamily, a.SizeBytes, a.SHA256)
	}
	w.Flush()

	fmt.Println("\nSBOM Metadata:")
	fmt.Printf("  Format:         %s\n", mf.SBOM.Format)
	if mf.SBOM.SHA256 != "" {
		fmt.Printf("  SHA256:         %s\n", mf.SBOM.SHA256)
	}
	if mf.SBOM.PackagesCount > 0 {
		fmt.Printf("  Total Packages: %d\n", mf.SBOM.PackagesCount)
	}
	if len(mf.SBOM.KeyPackages) > 0 {
		fmt.Printf("  Key Packages:   %v\n", mf.SBOM.KeyPackages)
	}
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to .tar.gz bundle archive")
	pubKeyPath := fs.String("pubkey", "", "Path to release public key PEM (optional if truststore provided)")
	trustStorePath := fs.String("truststore", "", "Path to truststore.yaml (optional if pubkey provided)")
	_ = fs.Parse(args)

	if *bundlePath == "" {
		fmt.Println("Error: --bundle flag is required")
		os.Exit(1)
	}
	if *pubKeyPath == "" && *trustStorePath == "" {
		fmt.Println("Error: either --pubkey or --truststore must be specified")
		os.Exit(1)
	}

	mf, err := readManifestFromBundle(*bundlePath)
	if err != nil {
		fmt.Printf("Failed reading manifest from bundle: %v\n", err)
		os.Exit(1)
	}

	var pubKey []byte
	if *trustStorePath != "" {
		ts, err := truststore.LoadFromFile(*trustStorePath)
		if err != nil {
			fmt.Printf("Failed loading trust store: %v\n", err)
			os.Exit(1)
		}
		validatedPub, err := ts.ValidateSigner(mf.KeyID, mf.SignerIdentity, time.Now().UTC())
		if err != nil {
			fmt.Printf("[SECURITY ALERT] Signer validation failed against trust store: %v\n", err)
			os.Exit(1)
		}
		pubKey = validatedPub
	} else {
		loadedPub, err := crypto.LoadPublicKeyPEM(*pubKeyPath)
		if err != nil {
			fmt.Printf("Failed loading public key: %v\n", err)
			os.Exit(1)
		}
		pubKey = loadedPub
	}

	canonicalBytes, err := mf.CanonicalBytes()
	if err != nil {
		fmt.Printf("Failed preparing canonical payload: %v\n", err)
		os.Exit(1)
	}

	if !crypto.Verify(pubKey, canonicalBytes, mf.Signature) {
		fmt.Println("[SECURITY ALERT] Signature verification FAILED! Untrusted or tampered bundle.")
		os.Exit(1)
	}

	fmt.Println("[VERIFIED] Cryptographic signature is VALID.")
	fmt.Printf("           Bundle ID: %s\n", mf.BundleID)
	fmt.Printf("           Signer:    %s\n", mf.SignerIdentity)
	if mf.KeyID != "" {
		fmt.Printf("           Key ID:    %s\n", mf.KeyID)
	}
}

func cmdIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to .tar.gz bundle archive")
	pubKeyPath := fs.String("pubkey", "", "Path to release public key PEM (optional if truststore provided)")
	trustStorePath := fs.String("truststore", "", "Path to truststore.yaml (optional if pubkey provided)")
	registryDir := fs.String("registry-dir", "", "Target GDC local registry directory")
	overwrite := fs.Bool("overwrite", false, "Allow overwriting existing catalog images")
	force := fs.Bool("force", false, "Alias for --overwrite")
	_ = fs.Parse(args)

	if *bundlePath == "" || *registryDir == "" {
		fmt.Println("Error: --bundle and --registry-dir flags are required")
		os.Exit(1)
	}
	if *pubKeyPath == "" && *trustStorePath == "" {
		fmt.Println("Error: either --pubkey or --truststore must be specified")
		os.Exit(1)
	}

	opts := ingest.IngestOptions{
		BundlePath:        *bundlePath,
		TargetRegistryDir: *registryDir,
		AllowOverwrite:    *overwrite || *force,
	}

	if *trustStorePath != "" {
		ts, err := truststore.LoadFromFile(*trustStorePath)
		if err != nil {
			fmt.Printf("Failed loading trust store: %v\n", err)
			os.Exit(1)
		}
		opts.TrustStore = ts
	} else {
		pubKey, err := crypto.LoadPublicKeyPEM(*pubKeyPath)
		if err != nil {
			fmt.Printf("Failed loading public key: %v\n", err)
			os.Exit(1)
		}
		opts.TrustedPubKey = pubKey
	}

	fmt.Println("[INGEST] Verifying cryptographic signatures and artifact integrity...")
	report, err := ingest.IngestBundleWithOptions(opts)
	if err != nil {
		fmt.Printf("[INGEST FAILED] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[SUCCESS] Release bundle verified and imported into GDC registry:")
	fmt.Printf("          Bundle ID:    %s\n", report.BundleID)
	fmt.Printf("          Signer:       %s\n", report.SignerIdentity)
	if report.KeyID != "" {
		fmt.Printf("          Key ID:       %s\n", report.KeyID)
	}
	fmt.Printf("          Catalog File: %s\n", report.CatalogFilePath)
	fmt.Printf("          Imported Images:\n")
	for _, img := range report.IngestedImages {
		fmt.Printf("          - %s (%s, SHA256: %s)\n", img.Name, img.Filename, img.SHA256)
	}
}

func cmdTrustStore(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: airgap-sync truststore <init|add|list|revoke> [flags]")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "init":
		fs := flag.NewFlagSet("truststore init", flag.ExitOnError)
		out := fs.String("out", "truststore.yaml", "Output path for trust store")
		_ = fs.Parse(subArgs)

		ts := truststore.New()
		if err := ts.SaveToFile(*out); err != nil {
			fmt.Printf("Failed initializing trust store: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[SUCCESS] Trust store initialized at: %s\n", *out)

	case "add":
		fs := flag.NewFlagSet("truststore add", flag.ExitOnError)
		storePath := fs.String("store", "truststore.yaml", "Path to trust store")
		pubKeyPath := fs.String("pubkey", "", "Path to public key PEM")
		identity := fs.String("identity", "", "Signer identity (email or URI)")
		scope := fs.String("scope", "all", "Authorized scope (e.g. all, os-images)")
		_ = fs.Parse(subArgs)

		if *pubKeyPath == "" || *identity == "" {
			fmt.Println("Error: --pubkey and --identity are required")
			os.Exit(1)
		}

		ts, err := truststore.LoadFromFile(*storePath)
		if err != nil {
			if os.IsNotExist(err) {
				ts = truststore.New()
			} else {
				fmt.Printf("Failed loading trust store: %v\n", err)
				os.Exit(1)
			}
		}

		pubKey, err := crypto.LoadPublicKeyPEM(*pubKeyPath)
		if err != nil {
			fmt.Printf("Failed loading public key: %v\n", err)
			os.Exit(1)
		}

		entry, err := ts.AddKey(pubKey, *identity, *scope)
		if err != nil {
			fmt.Printf("Failed adding key to trust store: %v\n", err)
			os.Exit(1)
		}

		if err := ts.SaveToFile(*storePath); err != nil {
			fmt.Printf("Failed saving trust store: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[SUCCESS] Added key to trust store:\n")
		fmt.Printf("          Key ID:   %s\n", entry.KeyID)
		fmt.Printf("          Identity: %s\n", entry.Identity)
		fmt.Printf("          Scope:    %s\n", entry.Scope)

	case "list":
		fs := flag.NewFlagSet("truststore list", flag.ExitOnError)
		storePath := fs.String("store", "truststore.yaml", "Path to trust store")
		_ = fs.Parse(subArgs)

		ts, err := truststore.LoadFromFile(*storePath)
		if err != nil {
			fmt.Printf("Failed loading trust store: %v\n", err)
			os.Exit(1)
		}

		keys := ts.ListKeys()
		fmt.Printf("Trust Store: %s (%d keys)\n\n", *storePath, len(keys))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "KEY ID\tIDENTITY\tSCOPE\tSTATUS\tADDED AT")
		for _, k := range keys {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				k.KeyID, k.Identity, k.Scope, k.Status, k.AddedAt.Format("2006-01-02 15:04:05"))
		}
		w.Flush()

	case "revoke":
		fs := flag.NewFlagSet("truststore revoke", flag.ExitOnError)
		storePath := fs.String("store", "truststore.yaml", "Path to trust store")
		keyID := fs.String("key-id", "", "Key ID to revoke")
		reason := fs.String("reason", "", "Revocation reason")
		_ = fs.Parse(subArgs)

		if *keyID == "" || *reason == "" {
			fmt.Println("Error: --key-id and --reason are required")
			os.Exit(1)
		}

		ts, err := truststore.LoadFromFile(*storePath)
		if err != nil {
			fmt.Printf("Failed loading trust store: %v\n", err)
			os.Exit(1)
		}

		if err := ts.RevokeKey(*keyID, *reason); err != nil {
			fmt.Printf("Failed revoking key: %v\n", err)
			os.Exit(1)
		}

		if err := ts.SaveToFile(*storePath); err != nil {
			fmt.Printf("Failed saving trust store: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[SUCCESS] Revoked key %s (Reason: %s)\n", *keyID, *reason)

	default:
		fmt.Printf("Unknown truststore action: %s\n", sub)
		os.Exit(1)
	}
}

func readManifestFromBundle(bundlePath string) (*manifest.BundleManifest, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	// In secure archives, manifest.yaml is the very first entry
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("failed reading archive header: %w", err)
	}

	cleanName := path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/"))
	if cleanName != "manifest.yaml" {
		return nil, fmt.Errorf("archive layout error: expected 'manifest.yaml' as first entry, found '%s'", hdr.Name)
	}

	data, err := io.ReadAll(io.LimitReader(tr, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed reading manifest payload: %w", err)
	}

	var mf manifest.BundleManifest
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("failed parsing manifest YAML: %w", err)
	}

	return &mf, nil
}
