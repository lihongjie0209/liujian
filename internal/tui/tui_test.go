package tui

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/firewall"
	"github.com/lihongjie0209/liujian/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

func TestModelBrowseFilterAndDetails(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	firstID, err := db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: "http://example.test/first?source=tui", Proto: "HTTP/1.1", Status: 200, ResponseBody: []byte("first response")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(firstID, store.Message{Time: time.Now(), FromClient: true, Type: 1, Body: []byte("hello socket")}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Save(&store.Session{Time: time.Now(), Duration: 125 * time.Millisecond, Method: "POST", URL: "https://example.test/second", Proto: "HTTP/2.0", Status: 201, RequestHeaders: http.Header{"X-Test": {"yes"}}, ResponseHeaders: http.Header{"Content-Type": {"text/plain"}}, ResponseBody: []byte("second response")}); err != nil {
		t.Fatal(err)
	}
	m := model{store: db, width: 120, height: 30}
	update := func(msg tea.Msg) {
		t.Helper()
		result, _ := m.Update(msg)
		m = result.(model)
	}
	update(tickMsg{})
	if view := m.View(); !strings.Contains(view, "GET first?source=tui") || !strings.Contains(view, "POST second") || !strings.Contains(view, "Waterfall") || !strings.Contains(view, "125.0 ms") {
		t.Fatalf("missing captured sessions: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyEnter})
	if view := m.View(); !strings.Contains(view, "X-Test: yes") {
		t.Fatalf("missing session details: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyTab})
	update(tea.KeyMsg{Type: tea.KeyTab})
	update(tea.KeyMsg{Type: tea.KeyTab})
	if view := m.View(); !strings.Contains(view, "second response") {
		t.Fatalf("missing response tab: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyTab})
	update(tea.KeyMsg{Type: tea.KeyTab})
	if view := m.View(); !strings.Contains(view, "Total:") || !strings.Contains(view, "125.0 ms") {
		t.Fatalf("missing timing tab: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyEsc})
	update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	for _, r := range "first" {
		update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	update(tea.KeyMsg{Type: tea.KeyEnter})
	update(tickMsg{})
	if view := m.View(); !strings.Contains(view, "GET first?source=tui") || strings.Contains(view, "POST second") {
		t.Fatalf("filter did not narrow sessions: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyEnter})
	update(tea.KeyMsg{Type: tea.KeyTab})
	if view := m.View(); !strings.Contains(view, "source: tui") {
		t.Fatalf("missing query parameter in payload: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyTab})
	if view := m.View(); !strings.Contains(view, "first response") {
		t.Fatalf("missing filtered session response: %s", view)
	}
	for range 4 {
		update(tea.KeyMsg{Type: tea.KeyTab})
	}
	if view := m.View(); !strings.Contains(view, "WS → text") {
		t.Fatalf("missing WebSocket event row: %s", view)
	}
	update(tea.KeyMsg{Type: tea.KeyEnter})
	if view := m.View(); !strings.Contains(view, "hello socket") {
		t.Fatalf("missing WebSocket event detail: %s", view)
	}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("quit key did not return a command")
	}
}

func TestTypeFilterAndScriptOutput(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, item := range []store.Session{
		{Time: time.Now(), Method: "GET", URL: "https://example.test/index.html", Status: 200, ResponseHeaders: http.Header{"Content-Type": {"text/html"}}},
		{Time: time.Now(), Method: "POST", URL: "https://example.test/api/item", Status: 200, ResponseHeaders: http.Header{"Content-Type": {"application/json"}}, RequestBody: []byte("request-key"), ResponseBody: []byte("response-key"), ScriptRuns: []store.ScriptRun{{Name: "decrypt", Phase: "response", Display: `{"plain":"hello"}`}}},
	} {
		if _, err := db.Save(&item); err != nil {
			t.Fatal(err)
		}
	}
	m := model{store: db, width: 120, height: 30}
	update := func(msg tea.Msg) { got, _ := m.Update(msg); m = got.(model) }
	update(tickMsg{})
	update(tea.KeyMsg{Type: tea.KeyRight})
	if len(m.rows) != 1 || !strings.Contains(m.rows[0].URL, "/api/item") || !strings.Contains(m.View(), "Fetch/XHR") {
		t.Fatalf("type filter failed: %s", m.View())
	}
	m.filter = "resp:response-key"
	update(tickMsg{})
	if len(m.rows) != 1 {
		t.Fatalf("response search failed: %+v", m.rows)
	}
	m.filter = "req:missing"
	update(tickMsg{})
	if len(m.rows) != 0 {
		t.Fatalf("request search unexpectedly matched: %+v", m.rows)
	}
	m.filter = "req:request-key"
	update(tickMsg{})
	update(tea.KeyMsg{Type: tea.KeyEnter})
	for i := 0; i < 10 && m.currentTab() != "Scripts"; i++ {
		update(tea.KeyMsg{Type: tea.KeyTab})
	}
	if view := m.View(); !strings.Contains(view, "decrypt") || !strings.Contains(view, "hello") {
		t.Fatalf("script output missing: %s", view)
	}
}

func TestFormattedStructuredBodiesAndSSEEventDetail(t *testing.T) {
	stripANSI := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	jsonText := stripANSI.ReplaceAllString(formatted([]byte(`{"nested":{"value":1}}`), "application/json", false), "")
	if !strings.Contains(jsonText, "\n  \"nested\": {") {
		t.Fatalf("JSON was not formatted: %q", jsonText)
	}
	htmlText := stripANSI.ReplaceAllString(formatted([]byte(`<html><body><p>hello</p></body></html>`), "text/html", false), "")
	if !strings.Contains(htmlText, "\n") || !strings.Contains(htmlText, "<p>") {
		t.Fatalf("HTML was not formatted: %q", htmlText)
	}
	if !strings.Contains(formatted([]byte(`{"a":1}`), "application/json", false), "\x1b[") {
		t.Fatal("JSON syntax highlighting missing")
	}
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: "http://example.test/events", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(id, store.Message{Time: time.Now(), Protocol: "sse", Name: "update", EventID: "42", Body: []byte(`{"value":1}`)}); err != nil {
		t.Fatal(err)
	}
	m := model{store: db, width: 100, height: 30}
	for _, msg := range []tea.Msg{tickMsg{}, tea.KeyMsg{Type: tea.KeyEnter}} {
		updated, _ := m.Update(msg)
		m = updated.(model)
	}
	for range 6 {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = updated.(model)
	}
	if !strings.Contains(m.View(), "SSE update id=42") {
		t.Fatalf("missing SSE event row: %s", m.View())
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if !strings.Contains(stripANSI.ReplaceAllString(m.View(), ""), "\"value\": 1") {
		t.Fatalf("missing formatted SSE event detail: %s", m.View())
	}
}

func TestListenerGuide(t *testing.T) {
	tests := []struct {
		name      string
		listeners Listeners
		want      []string
	}{
		{
			name:      "LAN defaults and extra ports",
			listeners: Listeners{IP: "192.168.1.20", DNSPort: 53, HTTPPorts: []int{80, 8081}, HTTPSPorts: []int{443, 9443}, ProxyPort: 8080},
			want:      []string{"DNS UDP/TCP 192.168.1.20:53", "HTTP :80, :8081", "HTTPS :443, :9443", "Proxy 192.168.1.20:8080", "set phone DNS to 192.168.1.20", "http://ca-proxy.test/ca.crt"},
		},
		{
			name:      "all interfaces",
			listeners: Listeners{IP: "0.0.0.0", PhoneIPs: []string{"192.168.1.20", "10.0.0.4"}, DNSPort: 53, HTTPPorts: []int{80}, HTTPSPorts: []int{443}, ProxyPort: 8080},
			want:      []string{"DNS UDP/TCP 0.0.0.0:53", "All IPv4 interfaces", "reachable LAN IP: 192.168.1.20, 10.0.0.4", "--dns-answer-rule CIDR=LOCAL_IP", "http://ca-proxy.test/ca.crt"},
		},
		{
			name:      "explicit DNS rule",
			listeners: Listeners{IP: "0.0.0.0", PhoneIPs: []string{"192.168.1.20"}, DNSPort: 53, HTTPPorts: []int{80}, HTTPSPorts: []int{443}, ProxyPort: 8080, DNSAnswerRules: []string{"10.8.0.0/16=192.168.1.20"}},
			want:      []string{"explicit rules: 10.8.0.0/16=192.168.1.20"},
		},
		{
			name:      "test only listener",
			listeners: Listeners{IP: "127.0.0.1", DNSPort: 10053, HTTPPorts: []int{18080}, HTTPSPorts: []int{18443}, ProxyPort: 18081},
			want:      []string{"DNS UDP/TCP 127.0.0.1:10053", "local-only", "require port 53", "--listen-ip", "--dns-port 53", "http://ca-proxy.test:18080/ca.crt"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := model{live: true, listeners: tt.listeners, width: 120, height: 30}
			view := m.View()
			for _, want := range tt.want {
				if !strings.Contains(view, want) {
					t.Errorf("missing %q in TUI: %s", want, view)
				}
			}
		})
	}
}

func TestParseFilterFields(t *testing.T) {
	query := parseFilter("url:/api proto:https method:POST status:201 client:192.168.1.8 error")
	if query.URL != "/api" || query.Protocol != "https" || query.Method != "POST" || query.Status != "201" || query.Client != "192.168.1.8" || query.Text != "error" {
		t.Fatalf("parsed filter = %+v", query)
	}
	guide := model{live: true, listeners: Listeners{IP: "0.0.0.0", DNSPort: 53, AllowHosts: []string{"*.example.test"}, AllowClients: []string{"192.168.1.8"}}, width: 120, height: 30}.View()
	if !strings.Contains(guide, "Capture targets") || !strings.Contains(guide, "Capture clients") {
		t.Fatalf("allowlist missing from TUI: %s", guide)
	}
}

func TestFirewallStatusRefreshInTUI(t *testing.T) {
	m := model{live: true, listeners: Listeners{IP: "0.0.0.0", DNSPort: 53, HTTPPorts: []int{80}, HTTPSPorts: []int{443}, ProxyPort: 8080}, width: 120, height: 30}
	if !strings.Contains(m.View(), "Firewall Checking") {
		t.Fatalf("initial firewall check is not shown: %s", m.View())
	}
	updated, _ := m.Update(firewallResultMsg{status: firewall.Status{Message: "No program allow rule found"}})
	m = updated.(model)
	if !strings.Contains(m.View(), "Firewall No program allow rule found") {
		t.Fatal("firewall warning is not shown")
	}
	_, cmd := m.Update(firewallTickMsg{})
	if cmd == nil {
		t.Fatal("periodic firewall check was not scheduled")
	}
}

func TestTLSFailuresShownAsSummary(t *testing.T) {
	m := model{live: true, listeners: Listeners{IP: "0.0.0.0", DNSPort: 53, HTTPPorts: []int{80}, HTTPSPorts: []int{443}, ProxyPort: 8080, TLSFailureCount: func() uint64 { return 12 }}, width: 120, height: 30}
	if !strings.Contains(m.View(), "12 handshake failures") {
		t.Fatal("TLS failure summary is not shown in live TUI")
	}
}

func TestCompromisedCAStatusShownInGuide(t *testing.T) {
	m := model{live: true, listeners: Listeners{IP: "0.0.0.0", DNSPort: 53, CACompromised: true, HTTPPorts: []int{80}, HTTPSPorts: []int{443}, ProxyPort: 8080}, width: 120, height: 30}
	if !strings.Contains(m.View(), "CA status") || !strings.Contains(m.View(), "Publicly compromised test key") {
		t.Fatalf("CA status missing from live guide: %s", m.View())
	}
}

func TestTLSFailureCanBeOpenedFromNetworkList(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Save(&store.Session{Time: time.Now(), Method: "TLS", URL: "tls://api.example.test", Proto: "TLS", ClientAddr: "10.0.0.2:1234", Error: "remote error: tls: unknown certificate", ErrorCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	m := model{store: db, width: 120, height: 30}
	for _, msg := range []tea.Msg{tickMsg{}, tea.KeyMsg{Type: tea.KeyEnter}} {
		updated, _ := m.Update(msg)
		m = updated.(model)
	}
	if !strings.Contains(m.View(), "unknown certificate") || !strings.Contains(m.View(), "10.0.0.2:1234") || !strings.Contains(m.View(), "Occurrences:  2") || !strings.Contains(m.View(), "[Error]") {
		t.Fatalf("TLS failure detail is incomplete: %s", m.View())
	}
}
