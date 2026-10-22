package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Manager struct {
	root   *x509.Certificate
	signer crypto.Signer
	chain  [][]byte
	mu     sync.Mutex
	cache  map[string]*tls.Certificate
}

func LoadOrCreate(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "ca.pem")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data, err = generate()
		if err != nil {
			return nil, err
		}
		if err = writeAtomic(path, data); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return parse(data)
}

func Import(dir, certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	data := append(append([]byte(nil), keyPEM...), certPEM...)
	if _, err = parse(data); err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "ca.pem"), data)
}

func Export(dir, output string) error {
	m, err := Select(dir, DefaultProfile, false)
	if err != nil {
		return err
	}
	return m.Export(output)
}

func (m *Manager) Export(output string) error {
	return writeAtomic(output, m.CertificatePEM())
}

func (m *Manager) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.root.Raw})
}

func (m *Manager) Root() *x509.Certificate { return m.root }

func (m *Manager) Certificate(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, errors.New("missing certificate hostname")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.cache[host]; c != nil && c.Leaf != nil && time.Until(c.Leaf.NotAfter) > time.Hour {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	end := now.Add(24 * time.Hour)
	if end.After(m.root.NotAfter) {
		end = m.root.NotAfter
	}
	if !end.After(now) {
		return nil, errors.New("CA has expired")
	}
	t := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: end,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		t.IPAddresses = []net.IP{ip}
	} else {
		t.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, t, m.root, key.Public(), m.signer)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: append([][]byte{der}, m.chain...), PrivateKey: key, Leaf: leaf}
	if len(m.cache) >= 512 {
		clear(m.cache)
	}
	m.cache[host] = c
	return c, nil
}

func parse(data []byte) (*Manager, error) {
	var certs [][]byte
	var signer crypto.Signer
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		switch block.Type {
		case "CERTIFICATE":
			certs = append(certs, block.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			var ok bool
			signer, ok = k.(crypto.Signer)
			if !ok {
				return nil, errors.New("unsupported CA private key")
			}
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer = k
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer = k
		}
	}
	if len(certs) == 0 || signer == nil {
		return nil, errors.New("CA certificate and unencrypted private key are required")
	}
	root, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, err
	}
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate cannot sign leaf certificates")
	}
	if now := time.Now(); now.Before(root.NotBefore) || now.After(root.NotAfter) {
		return nil, errors.New("CA certificate is not currently valid")
	}
	pubA, err := x509.MarshalPKIXPublicKey(root.PublicKey)
	if err != nil {
		return nil, err
	}
	pubB, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	if string(pubA) != string(pubB) {
		return nil, errors.New("CA certificate and private key do not match")
	}
	return &Manager{root: root, signer: signer, chain: certs, cache: make(map[string]*tls.Certificate)}, nil
}

func generate() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ca-proxy local CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, t, t, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".ca-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	return nil
}
