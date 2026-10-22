package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lihongjie0209/liujian/internal/ca"
)

func TestCreateCAAndDiagnoseLocalTLS(t *testing.T) {
	dir := t.TempDir()
	create := rootCommand()
	create.SetArgs([]string{"--data-dir", dir, "ca", "create"})
	if err := create.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil || len(data) == 0 {
		t.Fatalf("new CA not saved: %v", err)
	}
	if err := create.Execute(); err == nil {
		t.Fatal("existing CA was overwritten")
	}
	manager, err := ca.Select(dir, ca.DefaultProfile, false)
	if err != nil {
		t.Fatal(err)
	}
	compromised, err := ca.IsCompromisedIssuer(manager.Root())
	if err != nil || compromised {
		t.Fatalf("new CA marked compromised: %v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	var output bytes.Buffer
	diagnose := rootCommand()
	diagnose.SetOut(&output)
	diagnose.SetArgs([]string{"--data-dir", dir, "ca", "diagnose", "127.0.0.1", "--connect-to", server.Listener.Addr().String()})
	if err := diagnose.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Publicly compromised test key: false") || !strings.Contains(output.String(), "Upstream TLS:") || !strings.Contains(output.String(), "System trust:") {
		t.Fatalf("diagnostic output: %s", output.String())
	}
}
