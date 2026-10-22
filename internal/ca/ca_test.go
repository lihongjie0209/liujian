package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedProfilesAndPrecedence(t *testing.T) {
	for _, name := range Profiles() {
		t.Run(name, func(t *testing.T) {
			manager, err := LoadBuiltin(name)
			if err != nil {
				t.Fatal(err)
			}
			compromised, err := IsCompromisedIssuer(manager.Root())
			if err != nil || !compromised {
				t.Fatalf("embedded compromised issuer was not identified: %v", err)
			}
			leaf, err := manager.Certificate("example.test")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(name, "TLS") {
				if len(leaf.Certificate) != 3 {
					t.Fatalf("TLS certificate chain has %d certificates, want 3", len(leaf.Certificate))
				}
				crossSign, err := x509.ParseCertificate(leaf.Certificate[2])
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.Root().CheckSignatureFrom(crossSign); err != nil {
					t.Fatalf("issuing CA does not chain through cross-sign: %v", err)
				}
				pool := x509.NewCertPool()
				pool.AddCert(manager.Root())
				if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "example.test", Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if _, err := LoadBuiltin("unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	dir := t.TempDir()
	defaultCA, err := Select(dir, DefaultProfile, false)
	if err != nil {
		t.Fatal(err)
	}
	if defaultCA.Root().Subject.CommonName != "EM DV TLS CA - G3C" {
		t.Fatalf("unexpected default CA: %s", defaultCA.Root().Subject.CommonName)
	}
	local, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := Select(dir, DefaultProfile, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(selected.Root().Raw) != string(local.Root().Raw) {
		t.Fatal("local CA did not override embedded default")
	}
	selected, err = Select(dir, DefaultProfile, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(selected.Root().Raw) != string(defaultCA.Root().Raw) {
		t.Fatal("explicit profile did not override local CA")
	}
}

func TestImportAndIssueCertificate(t *testing.T) {
	source := t.TempDir()
	original, err := LoadOrCreate(source)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := os.ReadFile(filepath.Join(source, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(combined)
	if keyBlock == nil {
		t.Fatal("missing CA key")
	}
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err = os.WriteFile(certPath, original.CertificatePEM(), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err = Import(target, certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOrCreate(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Root().Raw) != string(original.Root().Raw) {
		t.Fatal("imported CA differs")
	}
	leaf, err := loaded.Certificate("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(loaded.Root())
	if _, err = leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.test", Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certPath, other.CertificatePEM(), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Import(t.TempDir(), certPath, keyPath); err == nil {
		t.Fatal("mismatched key accepted")
	}
}
