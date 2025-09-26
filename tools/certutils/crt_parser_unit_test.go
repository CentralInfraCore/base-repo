package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func Test_printHelp_DoesNotPanic(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	printHelp()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if out == "" {
		t.Fatal("help output empty")
	}
}

func Test_main_VerboseYAML(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// reset default FlagSet to avoid "flag redefined"
	flag.CommandLine = flag.NewFlagSet("crt_parser_test_v", flag.ContinueOnError)
	os.Args = []string{"crt_parser", "-v"}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	main()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if strings.TrimSpace(out) == "" {
		t.Fatalf("verbose output empty")
	}
}

func Test_main_CertPath_YAML(t *testing.T) {
	// self-signed cert generálás ideiglenes fájlba
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "cert.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// reset default FlagSet to avoid "flag redefined"
	flag.CommandLine = flag.NewFlagSet("crt_parser_test_cert", flag.ContinueOnError)
	os.Args = []string{"crt_parser", "-cert", p}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	main()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	// minimális sanity: legyen nem üres és strukturált
	if strings.TrimSpace(out) == "" || !strings.Contains(out, ":") {
		t.Fatalf("unexpected YAML-like output:\n%s", out)
	}
	_ = io.Discard // import guard
}
