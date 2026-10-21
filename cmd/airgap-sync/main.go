package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/uday68/gdc-airgap-sync/pkg/bundler"
	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/ingest"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
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
  verify                   Validate cryptographic signature and artifact SHA-256 digests
  ingest                   Verify and import release bundle into GDC local registry

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

	fmt.Println("[KEYGEN] Ed25519 signing keypair generated successfully:")
	fmt.Printf("         Private Key: %s (Keep secure in Connected Zone)\n", privPath)
	fmt.Printf("         Public Key:  %s (Deploy to Air-Gapped GDC clusters)\n", pubPath)
}

func cmdBundle(args []string) {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	name := fs.String("name", "", "Artifact image name (e.g. ubuntu-22.04)")
	file := fs.String("file", "", "Path to source disk image file")
	key := fs.String("key", "", "Path to release private key PEM")
	out := fs.String("out", "", "Output path for signed bundle (.tar.gz)")
	osFamily := fs.String("os", "linux", "OS Family (linux, windows)")
	desc := fs.String("desc", "GDC Verified Gold Image", "Image description")
	signer := fs.String("signer", "releng@cloud.google.com", "Signer identity")
	_ = fs.Parse(args)

	if *name == "" || *file == "" || *key == "" || *out == "" {
		fmt.Println("Error: --name, --file, --key, and --out flags are all required")
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
	})
	if err != nil {
		fmt.Printf("Bundle creation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[SUCCESS] Air-gapped release bundle created:")
	fmt.Printf("          Bundle ID:    %s\n", mf.BundleID)
	fmt.Printf("          Signer:       %s\n", mf.SignerIdentity)
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
	fmt.Printf("Created:         %s\n", mf.CreatedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Printf("Origin:          %s\n", mf.Origin)
	fmt.Printf("Signer Identity: %s\n", mf.SignerIdentity)
	fmt.Printf("Signature:       %s\n", mf.Signature)
	fmt.Println("\nArtifacts:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tFILENAME\tOS\tSIZE (BYTES)\tSHA256 CHECKSUM")
	for _, a := range mf.Artifacts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", a.Name, a.Filename, a.OSFamily, a.SizeBytes, a.SHA256)
	}
	w.Flush()

	fmt.Println("\nSBOM Metadata:")
	fmt.Printf("  Format:         %s (Version: %s)\n", mf.SBOM.Format, mf.SBOM.SpecVersion)
	fmt.Printf("  Total Packages: %d\n", mf.SBOM.PackagesCount)
	fmt.Printf("  Key Packages:   %v\n", mf.SBOM.KeyPackages)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to .tar.gz bundle archive")
	pubKeyPath := fs.String("pubkey", "", "Path to release public key PEM")
	_ = fs.Parse(args)

	if *bundlePath == "" || *pubKeyPath == "" {
		fmt.Println("Error: --bundle and --pubkey flags are required")
		os.Exit(1)
	}

	pubKey, err := crypto.LoadPublicKeyPEM(*pubKeyPath)
	if err != nil {
		fmt.Printf("Failed loading public key: %v\n", err)
		os.Exit(1)
	}

	mf, err := readManifestFromBundle(*bundlePath)
	if err != nil {
		fmt.Printf("Failed reading manifest from bundle: %v\n", err)
		os.Exit(1)
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
}

func cmdIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to .tar.gz bundle archive")
	pubKeyPath := fs.String("pubkey", "", "Path to release public key PEM")
	registryDir := fs.String("registry-dir", "", "Target GDC local registry directory")
	_ = fs.Parse(args)

	if *bundlePath == "" || *pubKeyPath == "" || *registryDir == "" {
		fmt.Println("Error: --bundle, --pubkey, and --registry-dir flags are all required")
		os.Exit(1)
	}

	pubKey, err := crypto.LoadPublicKeyPEM(*pubKeyPath)
	if err != nil {
		fmt.Printf("Failed loading public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[INGEST] Verifying cryptographic signatures and artifact integrity...")
	report, err := ingest.IngestBundle(*bundlePath, pubKey, *registryDir)
	if err != nil {
		fmt.Printf("[INGEST FAILED] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[SUCCESS] Release bundle verified and imported into GDC registry:")
	fmt.Printf("          Bundle ID:    %s\n", report.BundleID)
	fmt.Printf("          Signer:       %s\n", report.SignerIdentity)
	fmt.Printf("          Catalog File: %s\n", report.CatalogFilePath)
	fmt.Printf("          Imported Images:\n")
	for _, img := range report.IngestedImages {
		fmt.Printf("          - %s (%s, SHA256: %s)\n", img.Name, img.Filename, img.SHA256)
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
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Clean(hdr.Name) == "manifest.yaml" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			var mf manifest.BundleManifest
			if err := yaml.Unmarshal(data, &mf); err != nil {
				return nil, err
			}
			return &mf, nil
		}
	}
	return nil, fmt.Errorf("manifest.yaml not found in archive")
}
