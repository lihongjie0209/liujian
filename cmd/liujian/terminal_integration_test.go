//go:build integration && linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestIntegrationHelperCLI(t *testing.T) {
	if os.Getenv("CA_PROXY_TEST_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		t.Fatal("missing CLI separator")
	}
	cmd := rootCommand()
	cmd.SetArgs(os.Args[separator+1:])
	if err := cmd.Execute(); err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

type terminalOutput struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func (o *terminalOutput) read(f *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			o.mu.Lock()
			_, _ = o.buffer.Write(buf[:n])
			o.mu.Unlock()
			select {
			case o.changed <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

func (o *terminalOutput) waitFor(t *testing.T, want string, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		o.mu.Lock()
		output := o.buffer.String()
		o.mu.Unlock()
		if strings.Contains(output, want) {
			return
		}
		select {
		case <-o.changed:
		case <-timer.C:
			if len(output) > 3000 {
				output = output[len(output)-3000:]
			}
			t.Fatalf("terminal did not show %q; recent output: %q", want, output)
		}
	}
}

func integrationPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestCLIProxyTUIAndHAR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	dir := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"terminal":"body"}`)
	}))
	defer upstream.Close()
	proxyPort := integrationPort(t)
	args := []string{"-test.run=TestIntegrationHelperCLI", "--", "--data-dir", dir, "run", "--upstream-dns", "127.0.0.1:1", "--dns-port", strconv.Itoa(integrationPort(t)), "--http-port", strconv.Itoa(integrationPort(t)), "--https-port", strconv.Itoa(integrationPort(t)), "--proxy-port", strconv.Itoa(proxyPort)}
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), "CA_PROXY_TEST_HELPER=1", "TERM=dumb")
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	output := &terminalOutput{changed: make(chan struct{}, 1)}
	go output.read(terminal)
	output.waitFor(t, "RECORDING", 5*time.Second)
	output.waitFor(t, "All IPv4 interfaces", 5*time.Second)
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	response, err := client.Get(upstream.URL + "/capture")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != `{"terminal":"body"}` {
		t.Fatalf("proxied response = %q, err=%v", body, err)
	}
	output.waitFor(t, "GET capture", 5*time.Second)
	if _, err := terminal.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}
	output.waitFor(t, "Request Headers", 3*time.Second)
	if _, err := terminal.Write([]byte("\t\t\t")); err != nil {
		t.Fatal(err)
	}
	output.waitFor(t, "Response source", 3*time.Second)
	if _, err := terminal.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("TUI did not quit")
	}
	harPath := filepath.Join(dir, "capture.har")
	export := exec.CommandContext(ctx, os.Args[0], "-test.run=TestIntegrationHelperCLI", "--", "--data-dir", dir, "sessions", "export", harPath)
	export.Env = append(os.Environ(), "CA_PROXY_TEST_HELPER=1")
	if data, err := export.CombinedOutput(); err != nil {
		t.Fatalf("HAR export: %v: %s", err, data)
	}
	data, err := os.ReadFile(harPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []struct {
				Request struct{ URL string }
			}
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Log.Entries) != 1 || !strings.Contains(doc.Log.Entries[0].Request.URL, "/capture") {
		t.Fatalf("exported HAR has wrong sessions: %s", data)
	}
}
