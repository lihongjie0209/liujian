package capture

import (
	"crypto/tls"
	"errors"
	"strings"

	"github.com/lihongjie0209/liujian/internal/ca"
)

func rejectCompromisedUpstream(state tls.ConnectionState) error {
	for _, cert := range state.PeerCertificates {
		bad, err := ca.IsCompromisedIssuer(cert)
		if err != nil {
			return err
		}
		if bad {
			return errors.New("upstream TLS chain uses a compromised eMudhra signing key")
		}
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		name := root.Subject.CommonName
		if name != "emSign Root TLS CA - G3" && name != "emSign ECC Root CA - G3" {
			continue
		}
		for _, org := range root.Subject.Organization {
			if strings.Contains(strings.ToLower(org), "emudhra") {
				return errors.New("upstream TLS chain ends at an affected eMudhra root")
			}
		}
	}
	return nil
}
