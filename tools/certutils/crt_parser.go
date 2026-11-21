// Command crt_parser prints an X.509 certificate as YAML: the parsed
// certificate fields under "certificate" and the key algorithm, size (RSA bits,
// 256 for Ed25519) and curve name (ECDSA) under "public_key".
//
// Usage: crt_parser [-cert <path>] [-v] [-h|--help]. -cert defaults to
// cert.crt; -v prints the build metadata instead. The file must hold a PEM
// CERTIFICATE block; any read or parse error exits with status 1.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Build metadata printed by -v. BuildID, CommitHash and Timestamp are set at
// link time by the golang.build-crt-parser target (-ldflags -X main.…);
// GPGSignature and CAFingerprint are placeholders nothing sets yet.
var (
	// BuildID identifies the build ("<version>-<commit>" when built by make).
	BuildID = "relay-2025-07-29-01"
	// CommitHash is the git commit the binary was built from.
	CommitHash = "unknown"
	// Timestamp is the UTC build time in RFC 3339 form.
	Timestamp = "unknown"
	// GPGSignature is a placeholder for a signature over the build.
	GPGSignature = "<PGP_SIGNATURE>"
	// CAFingerprint is a placeholder for the fingerprint of the signing CA.
	CAFingerprint = "<CA_FINGERPRINT>"
)

// BuildMeta is the YAML shape of the build metadata printed by -v.
type BuildMeta struct {
	BuildID       string `yaml:"build_id"`
	CommitHash    string `yaml:"commit"`
	Timestamp     string `yaml:"timestamp"`
	GPGSignature  string `yaml:"gpg_signature"`
	CAFingerprint string `yaml:"ca_fingerprint"`
}

// printHelp prints the usage text to stdout.
func printHelp() {
	exe := filepath.Base(os.Args[0])
	fmt.Printf("Usage: %s [options]\n", exe)
	fmt.Println("Options:")
	fmt.Println("  -h, --help        Show help message")
	fmt.Println("  -v                Show build metadata in YAML")
	fmt.Println("  -cert <path>      Path to certificate file (default: cert.crt)")
}

// main handles -h/--help and -v, otherwise reads the -cert file, parses the
// first PEM block as an X.509 certificate and prints it with its key info as
// YAML.
func main() {
	help := flag.Bool("h", false, "Show help")
	verbose := flag.Bool("v", false, "Show build metadata in YAML")
	certPath := flag.String("cert", "cert.crt", "Certificate file path")
	flag.Parse()

	for _, arg := range os.Args[1:] {
		if arg == "--help" {
			*help = true
		}
	}

	if *help {
		printHelp()
		return
	}

	if *verbose {
		meta := BuildMeta{
			BuildID:       BuildID,
			CommitHash:    CommitHash,
			Timestamp:     Timestamp,
			GPGSignature:  GPGSignature,
			CAFingerprint: CAFingerprint,
		}
		yamlData, _ := yaml.Marshal(meta)
		fmt.Println(string(yamlData))
		return
	}

	certPEM, err := os.ReadFile(*certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading certificate: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Fprintln(os.Stderr, "Error: invalid certificate format")
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	// Extract key algorithm and size as part of YAML output structure
	keyAlgo := cert.PublicKeyAlgorithm.String()
	keySize := 0
	curveName := ""
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = pub.Size() * 8
	case *ecdsa.PublicKey:
		curveName = pub.Curve.Params().Name
	case ed25519.PublicKey:
		keySize = 256
	}

	keyInfo := map[string]interface{}{
		"algorithm": keyAlgo,
		"size":      keySize,
		"curve":     curveName,
	}

	certMap := map[string]interface{}{
		"certificate": cert,
		"public_key":  keyInfo,
	}

	yamlData, err := yaml.Marshal(certMap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting to YAML: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(yamlData))
}
