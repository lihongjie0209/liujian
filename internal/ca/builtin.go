package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DefaultProfile is the built-in TLS CA used when no local CA was imported.
const DefaultProfile = "EM-DV-TLS-CA-G3C"

var profiles = []string{
	"EM-DV-TLS-CA-G3B",
	"EM-DV-TLS-CA-G3C",
	"EM-EV-TLS-CA-G3B",
	"EM-EV-TLS-CA-G3C",
	"EM-OV-TLS-CA-G3B",
	"EM-OV-TLS-CA-G3C",
	"EM-OV-CS-CA-G3B",
	"EM-OV-CS-CA-G3C",
}

//go:embed emudhra/*.pem
var builtinFiles embed.FS

var compromisedKeys struct {
	sync.Once
	fingerprints map[[32]byte]bool
	err          error
}

// IsCompromisedIssuer identifies the publicly disclosed eMudhra signing keys.
func IsCompromisedIssuer(cert *x509.Certificate) (bool, error) {
	compromisedKeys.Do(func() {
		compromisedKeys.fingerprints = make(map[[32]byte]bool)
		for _, name := range profiles {
			data, err := builtinFiles.ReadFile("emudhra/" + name + ".crt.pem")
			if err != nil {
				compromisedKeys.err = err
				return
			}
			block, _ := pem.Decode(data)
			if block == nil {
				compromisedKeys.err = fmt.Errorf("missing embedded certificate %s", name)
				return
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				compromisedKeys.err = err
				return
			}
			compromisedKeys.fingerprints[sha256.Sum256(cert.RawSubjectPublicKeyInfo)] = true
		}
	})
	if compromisedKeys.err != nil || cert == nil {
		return false, compromisedKeys.err
	}
	return compromisedKeys.fingerprints[sha256.Sum256(cert.RawSubjectPublicKeyInfo)], nil
}

// Profiles returns the embedded CA names. CS profiles are for code signing,
// and clients will reject TLS leaves issued by them.
func Profiles() []string { return append([]string(nil), profiles...) }

// LoadBuiltin loads one of the embedded, publicly compromised test CAs.
func LoadBuiltin(name string) (*Manager, error) {
	valid := false
	for _, p := range profiles {
		if p == name {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("unknown CA profile %q", name)
	}
	cert, err := builtinFiles.ReadFile("emudhra/" + name + ".crt.pem")
	if err != nil {
		return nil, err
	}
	key, err := builtinFiles.ReadFile("emudhra/" + name + ".key.pem")
	if err != nil {
		return nil, err
	}
	if strings.Contains(name, "TLS") {
		// The issuing CA chains through this cross-sign to emSign ECC Root CA - G3.
		// Clients cannot build that path when only the issuing CA is sent.
		crossSign, err := builtinFiles.ReadFile("emudhra/roottlscag3-cross.crt.pem")
		if err != nil {
			return nil, err
		}
		cert = append(cert, crossSign...)
	}
	return parse(append(append([]byte(nil), key...), cert...))
}

// Select uses an imported CA when present, otherwise the embedded default.
// An explicitly selected profile takes precedence over the imported CA.
func Select(dir, profile string, explicitProfile bool) (*Manager, error) {
	if !explicitProfile {
		data, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
		if err == nil {
			return parse(data)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return LoadBuiltin(profile)
}
