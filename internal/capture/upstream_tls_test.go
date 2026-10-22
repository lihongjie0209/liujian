package capture

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/lihongjie0209/liujian/internal/ca"
)

func TestRejectCompromisedUpstream(t *testing.T) {
	manager, err := ca.LoadBuiltin(ca.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{manager.Root()}}
	if err := rejectCompromisedUpstream(state); err == nil || !strings.Contains(err.Error(), "compromised eMudhra") {
		t.Fatalf("compromised issuer accepted: %v", err)
	}
	if err := rejectCompromisedUpstream(tls.ConnectionState{}); err != nil {
		t.Fatalf("empty chain rejected: %v", err)
	}
	affectedRoot := &x509.Certificate{Subject: pkix.Name{CommonName: "emSign Root TLS CA - G3", Organization: []string{"eMudhra Technologies Limited"}}}
	state = tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: "site.test"}}, affectedRoot}}}
	if err := rejectCompromisedUpstream(state); err == nil || !strings.Contains(err.Error(), "affected eMudhra root") {
		t.Fatalf("affected root accepted: %v", err)
	}
}
