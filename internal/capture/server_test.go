package capture

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/allowlist"
	"github.com/lihongjie0209/liujian/internal/ca"
	"github.com/lihongjie0209/liujian/internal/scripts"
	"github.com/lihongjie0209/liujian/internal/store"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

func TestScriptedHTTPRequestAndResponse(t *testing.T) {
	dir := t.TempDir()
	source := `function onRequest(request) { request.body = new Uint8Array([0, 255, 7]); request.headers["X-Script"] = ["yes"]; request.display = "request changed"; return request; }
function onResponse(response) { response.body = new Uint8Array([9, 0, 8]); response.headers["Content-Type"] = ["application/octet-stream"]; response.display = "response changed"; return response; }`
	if err := os.WriteFile(filepath.Join(dir, "modify.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(scripts.Config{Scripts: []scripts.Definition{{Name: "modify", File: "modify.js"}}})
	if err := os.WriteFile(filepath.Join(dir, "scripts.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
	runner, err := scripts.Load(filepath.Join(dir, "scripts.json"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != string([]byte{0, 255, 7}) || r.Header.Get("X-Script") != "yes" {
			t.Errorf("upstream request body=%v headers=%v", body, r.Header)
		}
		_, _ = w.Write([]byte("original"))
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	server := &Server{Config: Config{BodyLimit: 1024}, Store: db, Scripts: runner, transport: &http.Transport{Proxy: nil}}
	request := httptest.NewRequest("POST", upstream.URL+"/api", bytes.NewReader([]byte("input")))
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.serveHTTP(response, request, "http", target.Host)
	if response.Code != 200 || string(response.Body.Bytes()) != string([]byte{9, 0, 8}) {
		t.Fatalf("client response %d %v", response.Code, response.Body.Bytes())
	}
	rows, err := db.List(10, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("sessions: %+v, %v", rows, err)
	}
	session, err := db.Get(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.ScriptRuns) != 2 || session.ScriptRuns[0].Display != "request changed" || session.ScriptRuns[1].Display != "response changed" || string(session.RequestBody) != string([]byte{0, 255, 7}) || string(session.ResponseBody) != string([]byte{9, 0, 8}) {
		t.Fatalf("captured session: %+v", session)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestNonmatchingExplicitProxyTrafficPassesThroughWithoutCapture(t *testing.T) {
	hosts, err := allowlist.ParseHosts([]string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "direct upstream")
	}))
	defer upstream.Close()
	server := &Server{Config: Config{UpstreamDNS: "127.0.0.1:53", AllowHosts: hosts}, Store: db, transport: &http.Transport{Proxy: nil}}
	proxy := httptest.NewServer(server.guard(http.HandlerFunc(server.serveExplicit)))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	response, err := client.Get(upstream.URL + "/uncaptured")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT passthrough returned %d", response.StatusCode)
	}
	rows, err := db.List(20, "")
	if err != nil || len(rows) != 0 {
		t.Fatalf("uncaptured CONNECT created sessions: %+v, %v", rows, err)
	}
}

func TestAllowedCaptureRequiresTargetAndClient(t *testing.T) {
	hosts, err := allowlist.ParseHosts([]string{"api.example.test", "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	clients, err := allowlist.ParseClients([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Config: Config{AllowHosts: hosts, AllowClients: clients}}
	for _, tc := range []struct {
		host, remote string
		want         bool
	}{
		{"api.example.test", "192.168.1.42:51000", true},
		{"203.0.113.12", "192.168.1.42:51000", true},
		{"198.51.100.12", "192.168.1.42:51000", false},
		{"api.example.test", "192.168.2.42:51000", false},
	} {
		if got := s.allowedCapture(tc.host, tc.remote); got != tc.want {
			t.Errorf("allowedCapture(%q, %q) = %v, want %v", tc.host, tc.remote, got, tc.want)
		}
	}
}

func TestCaptureEntrypoints(t *testing.T) {
	dir := t.TempDir()
	manager, err := ca.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "id: 42\nevent: update\ndata: {\"value\":1}\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/ws" {
			c, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			for {
				typ, msg, err := c.ReadMessage()
				if err != nil {
					return
				}
				if err = c.WriteMessage(typ, msg); err != nil {
					return
				}
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream "+r.URL.Path)
	}))
	defer upstream.Close()
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, e := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if e != nil {
				return
			}
			defer c.Close()
			for {
				typ, msg, e := c.ReadMessage()
				if e != nil {
					return
				}
				if e = c.WriteMessage(typ, msg); e != nil {
					return
				}
			}
		}
		_, _ = io.WriteString(w, "secure")
	}))
	secure.EnableHTTP2 = true
	leaf, err := manager.Certificate("localhost")
	if err != nil {
		t.Fatal(err)
	}
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	secure.StartTLS()
	defer secure.Close()
	upRoots := x509.NewCertPool()
	upRoots.AddCert(manager.Root())
	db, err := store.Open(filepath.Join(dir, "store"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dnsPort, httpPort, httpsPort, proxyPort := freePort(t), freePort(t), freePort(t), freePort(t)
	httpExtraPort, httpsExtraPort := freePort(t), freePort(t)
	dnsAddr := net.JoinHostPort("127.0.0.1", itoa(dnsPort))
	upDNS := &dns.Server{Addr: dnsAddr, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			address := net.IPv4(203, 0, 113, 10)
			if r.Question[0].Name == "localhost." {
				address = net.IPv4(127, 0, 0, 1)
			}
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: address}}
		}
		_ = w.WriteMsg(m)
	})}
	upDNS.PacketConn, err = net.ListenPacket("udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	go upDNS.ActivateAndServe()
	defer upDNS.Shutdown()
	server := &Server{Config: Config{ListenIP: net.IPv4(127, 0, 0, 1), UpstreamDNS: dnsAddr, UpstreamRootCAs: upRoots, Exclude: []string{"*.skip.test"}, DNSPort: freePort(t), HTTPPort: httpPort, HTTPSPort: httpsPort, HTTPExtraPorts: []int{httpExtraPort}, HTTPSExtraPorts: []int{httpsExtraPort}, ProxyPort: proxyPort}, CA: manager, Store: db}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	proxyAddr := net.JoinHostPort("127.0.0.1", itoa(proxyPort))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, handshakeErr := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", itoa(httpsPort)), &tls.Config{ServerName: "denied.example.test"})
	if handshakeErr == nil {
		t.Fatal("untrusted TLS handshake unexpectedly succeeded")
	}
	failedDeadline := time.Now().Add(2 * time.Second)
	for {
		failures, listErr := db.List(10, "denied.example.test")
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(failures) > 0 {
			failure := failures[0]
			if failure.Proto != "TLS" || failure.Error == "" || failure.ErrorCount != 1 || failure.ClientAddr == "" {
				t.Fatalf("TLS failure was not captured: %+v", failure)
			}
			break
		}
		if time.Now().After(failedDeadline) {
			t.Fatal("TLS failure did not appear in captured sessions")
		}
		time.Sleep(10 * time.Millisecond)
	}
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL + "/explicit")
	if err != nil {
		t.Fatal(err)
	}
	checkBody(t, resp, "upstream /explicit")
	clientDeadline := time.Now().Add(2 * time.Second)
	for {
		rows, listErr := db.List(10, "/explicit")
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(rows) > 0 {
			if !strings.HasPrefix(rows[0].ClientAddr, "127.0.0.1:") {
				t.Fatalf("captured HTTP client address = %q", rows[0].ClientAddr)
			}
			break
		}
		if time.Now().After(clientDeadline) {
			t.Fatal("HTTP session did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err = client.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("SSE content type: %s", resp.Header.Get("Content-Type"))
	}
	streamEvent := make([]byte, len("id: 42\nevent: update\ndata: {\"value\":1}\n\n"))
	if _, err := io.ReadFull(resp.Body, streamEvent); err != nil {
		t.Fatal(err)
	}
	sseDeadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := db.List(10, "/events")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			eventSession, err := db.Get(rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(eventSession.Messages) == 1 {
				if !strings.HasPrefix(eventSession.ClientAddr, "127.0.0.1:") {
					t.Fatalf("captured SSE client address = %q", eventSession.ClientAddr)
				}
				m := eventSession.Messages[0]
				if m.Protocol != "sse" || m.Name != "update" || m.EventID != "42" || string(m.Body) != `{"value":1}` {
					t.Fatalf("captured SSE event: %+v", m)
				}
				break
			}
		}
		if time.Now().After(sseDeadline) {
			t.Fatal("SSE event was not captured while stream remained open")
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp.Body.Close()
	transparentURL := "http://127.0.0.1:" + itoa(httpPort) + "/transparent"
	req, _ := http.NewRequest("GET", transparentURL, nil)
	req.Host = strings.TrimPrefix(upstream.URL, "http://")
	resp, err = (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	checkBody(t, resp, "upstream /transparent")
	caReq, _ := http.NewRequest("GET", "http://127.0.0.1:"+itoa(httpPort)+"/ca.crt", nil)
	caReq.Host = "ca-proxy.test"
	caResp, err := (&http.Client{}).Do(caReq)
	if err != nil {
		t.Fatal(err)
	}
	caBody, _ := io.ReadAll(caResp.Body)
	caResp.Body.Close()
	if !strings.Contains(string(caBody), "BEGIN CERTIFICATE") {
		t.Fatalf("CA download: %q", caBody)
	}
	caExtraReq, _ := http.NewRequest("GET", "http://127.0.0.1:"+itoa(httpExtraPort)+"/ca.crt", nil)
	caExtraReq.Host = "ca-proxy.test:" + itoa(httpExtraPort)
	caExtraResp, err := (&http.Client{}).Do(caExtraReq)
	if err != nil {
		t.Fatal(err)
	}
	caExtraBody, _ := io.ReadAll(caExtraResp.Body)
	caExtraResp.Body.Close()
	if !strings.Contains(string(caExtraBody), "BEGIN CERTIFICATE") {
		t.Fatalf("CA download on custom HTTP port: %q", caExtraBody)
	}
	extraURL := "http://127.0.0.1:" + itoa(httpExtraPort) + "/extra"
	req, _ = http.NewRequest("GET", extraURL, nil)
	req.Host = strings.TrimPrefix(upstream.URL, "http://")
	resp, err = (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	checkBody(t, resp, "upstream /extra")
	rootPool := x509.NewCertPool()
	rootPool.AddCert(manager.Root())
	secureClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: rootPool}, ForceAttemptHTTP2: true}}
	secureURL := "https://localhost:" + itoa(secure.Listener.Addr().(*net.TCPAddr).Port)
	resp, err = secureClient.Get(secureURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("explicit HTTPS negotiated %s, want HTTP/2", resp.Proto)
	}
	checkBody(t, resp, "secure")
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "should not pass") }))
	defer untrusted.Close()
	badResp, err := secureClient.Get(untrusted.URL)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted upstream status %d, want 502", badResp.StatusCode)
	}
	h1Client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: rootPool}}}
	resp, err = h1Client.Get(secureURL + "/http1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("explicit HTTPS negotiated %s, want HTTP/1.1", resp.Proto)
	}
	checkBody(t, resp, "secure")
	for _, port := range []int{httpsPort, httpsExtraPort} {
		capturePort := port
		transparentClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool}, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", itoa(capturePort)))
		}}}
		resp, err = transparentClient.Get(secureURL + "/transparent")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("transparent HTTPS port %d negotiated %s, want HTTP/2", port, resp.Proto)
		}
		checkBody(t, resp, "secure")
	}
	wsURL := "ws://127.0.0.1:" + itoa(httpPort) + "/ws"
	ws, _, err := (&websocket.Dialer{}).Dial(wsURL, http.Header{"Host": []string{strings.TrimPrefix(upstream.URL, "http://")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = ws.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "hello" {
		t.Fatalf("WebSocket response %q", msg)
	}
	ws.Close()
	proxyWSDialer := &websocket.Dialer{Proxy: http.ProxyURL(proxyURL)}
	proxyWS, _, err := proxyWSDialer.Dial(strings.Replace(upstream.URL, "http://", "ws://", 1)+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = proxyWS.WriteMessage(websocket.TextMessage, []byte("via proxy")); err != nil {
		t.Fatal(err)
	}
	_, msg, err = proxyWS.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "via proxy" {
		t.Fatalf("proxy WebSocket response %q", msg)
	}
	proxyWS.Close()
	proxyWSSDialer := &websocket.Dialer{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: rootPool}}
	proxyWSS, _, err := proxyWSSDialer.Dial("wss://localhost:"+itoa(secure.Listener.Addr().(*net.TCPAddr).Port)+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = proxyWSS.WriteMessage(websocket.TextMessage, []byte("via secure proxy")); err != nil {
		t.Fatal(err)
	}
	_, msg, err = proxyWSS.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "via secure proxy" {
		t.Fatalf("proxy WSS response %q", msg)
	}
	proxyWSS.Close()
	wssDialer := &websocket.Dialer{NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", itoa(httpsExtraPort)))
	}, TLSClientConfig: &tls.Config{RootCAs: rootPool}}
	wss, _, err := wssDialer.Dial("wss://localhost:"+itoa(secure.Listener.Addr().(*net.TCPAddr).Port)+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = wss.WriteMessage(websocket.TextMessage, []byte("secure message")); err != nil {
		t.Fatal(err)
	}
	_, msg, err = wss.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "secure message" {
		t.Fatalf("WSS response %q", msg)
	}
	wss.Close()
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	answer, _, err := (&dns.Client{}).Exchange(query, net.JoinHostPort("127.0.0.1", itoa(server.Config.DNSPort)))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != "127.0.0.1" {
		t.Fatalf("DNS answer: %v", answer.Answer)
	}
	answer, _, err = (&dns.Client{Net: "tcp"}).Exchange(query, net.JoinHostPort("127.0.0.1", itoa(server.Config.DNSPort)))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 {
		t.Fatalf("DNS TCP answer: %v", answer.Answer)
	}
	for _, typ := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		q := new(dns.Msg).SetQuestion("example.com.", typ)
		a, _, e := (&dns.Client{}).Exchange(q, net.JoinHostPort("127.0.0.1", itoa(server.Config.DNSPort)))
		if e != nil {
			t.Fatal(e)
		}
		if a.Rcode != dns.RcodeSuccess || len(a.Answer) != 0 {
			t.Fatalf("type %d answer: %v", typ, a)
		}
	}
	excluded := new(dns.Msg).SetQuestion("api.skip.test.", dns.TypeA)
	answer, _, err = (&dns.Client{}).Exchange(excluded, net.JoinHostPort("127.0.0.1", itoa(server.Config.DNSPort)))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatalf("excluded DNS answer: %v", answer.Answer)
	}
	rows, err := db.List(20, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 12 {
		t.Fatalf("got %d sessions, want at least 12", len(rows))
	}
	wsRows, err := db.List(20, "/ws")
	if err != nil {
		t.Fatal(err)
	}
	if len(wsRows) < 4 {
		t.Fatalf("got %d WebSocket sessions, want 4", len(wsRows))
	}
	for _, row := range wsRows {
		saved, e := db.Get(row.ID)
		if e != nil {
			t.Fatal(e)
		}
		if len(saved.Messages) < 2 {
			t.Fatalf("session %d has %d messages", row.ID, len(saved.Messages))
		}
	}
}

func checkBody(t *testing.T, r *http.Response, want string) {
	t.Helper()
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 || string(data) != want {
		t.Fatalf("status=%d body=%q", r.StatusCode, data)
	}
}
func itoa(n int) string { return strconv.Itoa(n) }

func TestTLSHandshakeErrorsAreCountedWithoutLoggingEachConnection(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{Log: slog.New(slog.NewTextHandler(&logs, nil))}
	writer := httpErrorWriter{server: s}
	for range 3 {
		if _, err := writer.Write([]byte("http: TLS handshake error from 10.0.0.2:1234: remote error: tls: bad certificate\n")); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.TLSFailureCount(); got != 3 {
		t.Fatalf("TLS failure count = %d, want 3", got)
	}
	if logs.Len() != 0 {
		t.Fatalf("per-connection TLS errors leaked to log: %s", logs.String())
	}
	_, _ = writer.Write([]byte("http: unexpected listener warning\n"))
	if !strings.Contains(logs.String(), "unexpected listener warning") {
		t.Fatal("unexpected HTTP server warning was not logged")
	}
}

func TestRepeatedTLSErrorsAreGrouped(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{Store: db}
	writer := httpErrorWriter{server: s}
	for _, remote := range []string{"10.0.0.2:1234", "10.0.0.2:1235"} {
		s.tlsNames.Store(remote, "api.example.test")
		_, _ = writer.Write([]byte("http: TLS handshake error from " + remote + ": remote error: tls: unknown certificate\n"))
	}
	rows, err := db.List(10, "api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ErrorCount != 2 || rows[0].Proto != "TLS" || rows[0].ClientAddr != "10.0.0.2:1234" {
		t.Fatalf("grouped TLS failures = %+v", rows)
	}
	if s.TLSFailureCount() != 2 {
		t.Fatalf("total TLS failures = %d", s.TLSFailureCount())
	}
	key := "10.0.0.2\x00api.example.test\x00remote error: tls: unknown certificate"
	recent := s.tlsRecent[key]
	recent.first = time.Now().Add(-tlsErrorWindow)
	s.tlsRecent[key] = recent
	s.tlsNames.Store("10.0.0.2:1236", "api.example.test")
	_, _ = writer.Write([]byte("http: TLS handshake error from 10.0.0.2:1236: remote error: tls: unknown certificate\n"))
	rows, err = db.List(10, "api.example.test")
	if err != nil || len(rows) != 2 {
		t.Fatalf("expired TLS error group was not renewed: rows=%+v err=%v", rows, err)
	}
}
