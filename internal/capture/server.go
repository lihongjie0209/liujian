package capture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lihongjie0209/liujian/internal/allowlist"
	"github.com/lihongjie0209/liujian/internal/ca"
	"github.com/lihongjie0209/liujian/internal/dnsserver"
	"github.com/lihongjie0209/liujian/internal/mock"
	"github.com/lihongjie0209/liujian/internal/netutil"
	"github.com/lihongjie0209/liujian/internal/scripts"
	"github.com/lihongjie0209/liujian/internal/store"
	"github.com/soheilhy/cmux"
	sse "github.com/tmaxmax/go-sse"
	"golang.org/x/net/http2"
)

type Config struct {
	ListenIP                                net.IP
	UpstreamDNS                             string
	UpstreamRootCAs                         *x509.CertPool
	Exclude                                 []string
	AllowHosts                              allowlist.Hosts
	AllowClients                            allowlist.Clients
	DNSAnswerRules                          []dnsserver.AnswerRule
	DNSPort, HTTPPort, HTTPSPort, ProxyPort int
	HTTPExtraPorts, HTTPSExtraPorts         []int
	BodyLimit, FrameLimit                   int64
}

type Server struct {
	Config      Config
	CA          *ca.Manager
	Store       *store.Store
	Scripts     *scripts.Runner
	Mocks       *mock.Rules
	Log         *slog.Logger
	transport   *http.Transport
	tlsFailures atomic.Uint64
	tlsNames    sync.Map
	tlsErrorsMu sync.Mutex
	tlsRecent   map[string]recentTLSError
}

func (s *Server) TLSFailureCount() uint64 { return s.tlsFailures.Load() }

func (s *Server) Run(ctx context.Context) error {
	c := &s.Config
	if c.ListenIP == nil || c.ListenIP.To4() == nil {
		return errors.New("listen-ip must be an IPv4 address")
	}
	if c.UpstreamDNS == "" {
		return errors.New("upstream DNS is required")
	}
	if c.DNSPort == 0 {
		c.DNSPort = 53
	}
	upHost, upPort, err := net.SplitHostPort(c.UpstreamDNS)
	if err != nil || net.ParseIP(upHost) == nil {
		return errors.New("upstream DNS must be an IP:port address")
	}
	if upPort == fmt.Sprint(c.DNSPort) {
		conflicts, err := netutil.ConflictsWithListener(c.ListenIP, net.ParseIP(upHost))
		if err != nil {
			return err
		}
		if conflicts {
			return errors.New("upstream DNS cannot point to the capture DNS listener")
		}
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.ProxyPort == 0 {
		c.ProxyPort = 8080
	}
	if c.BodyLimit <= 0 {
		c.BodyLimit = 10 << 20
	}
	if c.FrameLimit <= 0 {
		c.FrameLimit = 1 << 20
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: dnsserver.Resolver(c.UpstreamDNS)}
	s.transport = &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableCompression: true, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, TLSClientConfig: &tls.Config{RootCAs: c.UpstreamRootCAs, VerifyConnection: rejectCompromisedUpstream}}
	defer s.transport.CloseIdleConnections()
	httpErrorLog := log.New(httpErrorWriter{server: s}, "", 0)
	ip := c.ListenIP.String()
	type endpoint struct {
		port     int
		scheme   string
		listener net.Listener
		server   *http.Server
	}
	ports := []endpoint{{port: c.HTTPPort, scheme: "http"}, {port: c.HTTPSPort, scheme: "https"}, {port: c.ProxyPort, scheme: "proxy"}}
	for _, p := range c.HTTPExtraPorts {
		ports = append(ports, endpoint{port: p, scheme: "http"})
	}
	for _, p := range c.HTTPSExtraPorts {
		ports = append(ports, endpoint{port: p, scheme: "https"})
	}
	seen := map[int]string{c.DNSPort: "DNS"}
	for i := range ports {
		p := &ports[i]
		if p.port < 1 || p.port > 65535 {
			return fmt.Errorf("invalid %s port %d", p.scheme, p.port)
		}
		if old := seen[p.port]; old != "" {
			return fmt.Errorf("port %d is configured for both %s and %s", p.port, old, p.scheme)
		}
		seen[p.port] = p.scheme
	}
	defer func() {
		for _, p := range ports {
			if p.listener != nil {
				_ = p.listener.Close()
			}
		}
	}()
	for i := range ports {
		p := &ports[i]
		var err error
		p.listener, err = net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(p.port)))
		if err != nil {
			return fmt.Errorf("%s listener on %d: %w", p.scheme, p.port, err)
		}
		if p.scheme == "proxy" {
			p.server = &http.Server{Handler: s.guard(http.HandlerFunc(s.serveExplicit)), ErrorLog: httpErrorLog, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
			continue
		}
		scheme := p.scheme
		p.server = &http.Server{Handler: s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, scheme, "") })), ErrorLog: httpErrorLog, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
		if scheme == "https" {
			p.server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				s.rememberTLSName(hello)
				remote := ""
				if hello.Conn != nil {
					remote = hello.Conn.RemoteAddr().String()
				}
				if !s.allowedCapture(hello.ServerName, remote) {
					return nil, errors.New("host or client is outside capture allowlist")
				}
				return s.CA.Certificate(hello.ServerName)
			}}
			p.server.ConnState = s.clearTLSName
			if err := http2.ConfigureServer(p.server, &http2.Server{}); err != nil {
				return err
			}
		}
	}
	dnsSrv := &dnsserver.Server{ListenIP: c.ListenIP, Port: c.DNSPort, Upstream: c.UpstreamDNS, Exclude: c.Exclude, AllowHosts: c.AllowHosts, AllowClients: c.AllowClients, AnswerRules: c.DNSAnswerRules}
	if err := dnsSrv.Start(); err != nil {
		return fmt.Errorf("DNS listener: %w", err)
	}
	defer dnsSrv.Shutdown()
	errCh := make(chan error, len(ports)*3)
	for _, p := range ports {
		p := p
		if p.scheme == "proxy" {
			mux := cmux.New(p.listener)
			mux.SetReadTimeout(10 * time.Second)
			socksListener := mux.Match(cmux.PrefixMatcher("\x05"))
			httpListener := mux.Match(cmux.Any())
			go func() {
				if e := p.server.Serve(httpListener); e != nil && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
					errCh <- e
				}
			}()
			go func() {
				if e := s.serveSOCKS(socksListener); e != nil && !errors.Is(e, net.ErrClosed) {
					errCh <- e
				}
			}()
			go func() {
				if e := mux.Serve(); e != nil && !errors.Is(e, net.ErrClosed) && ctx.Err() == nil {
					errCh <- e
				}
			}()
			continue
		}
		go func() {
			var e error
			if p.scheme == "https" {
				e = p.server.ServeTLS(p.listener, "", "")
			} else {
				e = p.server.Serve(p.listener)
			}
			if e != nil && !errors.Is(e, http.ErrServerClosed) {
				errCh <- e
			}
		}()
	}
	if s.Log != nil {
		s.Log.Info("capture listening", "ip", ip, "dns", c.DNSPort, "http", append([]int{c.HTTPPort}, c.HTTPExtraPorts...), "https", append([]int{c.HTTPSPort}, c.HTTPSExtraPorts...), "http_socks5_proxy", c.ProxyPort)
	}
	var runErr error
	select {
	case <-ctx.Done():
		runErr = nil
	case runErr = <-errCh:
	case runErr = <-dnsSrv.Errors:
	}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, p := range ports {
		_ = p.listener.Close()
		_ = p.server.Shutdown(stop)
	}
	return runErr
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid client", http.StatusForbidden)
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
			http.Error(w, "client is outside private network", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serveExplicit(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.serveConnect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "use CONNECT for HTTPS", http.StatusBadRequest)
		return
	}
	s.serve(w, r, "http", "")
}

func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	if host == "" {
		http.Error(w, "missing CONNECT host", http.StatusBadRequest)
		return
	}
	if !s.allowedCapture(host, r.RemoteAddr) {
		s.tunnelConnect(w, r)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	s.serveInterceptTunnel(conn, rw.Reader, host, authority)
}

func (s *Server) serveInterceptTunnel(conn net.Conn, reader *bufio.Reader, host, authority string) {
	wrapped := &bufferedConn{Conn: conn, reader: reader}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := reader.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if first[0] != 0x16 {
		handler := s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, "http", authority) }))
		listener := &oneConnListener{conn: wrapped, done: make(chan struct{})}
		_ = (&http.Server{Handler: handler, ErrorLog: log.New(httpErrorWriter{server: s}, "", 0), ReadHeaderTimeout: 10 * time.Second}).Serve(listener)
		return
	}
	tlsConn := tls.Server(wrapped, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := h.ServerName
		if name == "" {
			name = host
		}
		if !strings.EqualFold(name, host) {
			return nil, errors.New("CONNECT host and TLS SNI differ")
		}
		return s.CA.Certificate(name)
	}})
	if err = tlsConn.Handshake(); err != nil {
		s.recordTLSFailure(host, conn.RemoteAddr().String(), err.Error())
		if s.Log != nil {
			s.Log.Debug("CONNECT TLS failed", "error", err)
		}
		return
	}
	handler := s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, "https", authority) }))
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	listener := &oneConnListener{conn: tlsConn, done: make(chan struct{})}
	_ = (&http.Server{Handler: handler, ErrorLog: log.New(httpErrorWriter{server: s}, "", 0), ReadHeaderTimeout: 10 * time.Second}).Serve(listener)
}

func (s *Server) tunnelConnect(w http.ResponseWriter, r *http.Request) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: dnsserver.Resolver(s.Config.UpstreamDNS)}
	upstream, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, &bufferedConn{Conn: client, reader: rw.Reader})
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.SetReadDeadline(time.Now())
	<-done
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type oneConnListener struct {
	conn       net.Conn
	acceptOnce sync.Once
	closeOnce  sync.Once
	done       chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.acceptOnce.Do(func() { c = &trackedConn{Conn: l.conn, listener: l} })
	if c == nil {
		<-l.done
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *oneConnListener) Close() error   { l.closeOnce.Do(func() { close(l.done) }); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type trackedConn struct {
	net.Conn
	listener *oneConnListener
}

func (c *trackedConn) Close() error { err := c.Conn.Close(); _ = c.listener.Close(); return err }

func (s *Server) serve(w http.ResponseWriter, r *http.Request, scheme, connectHost string) {
	if strings.EqualFold(stripPort(r.Host), "ca-proxy.test") && r.URL.Path == "/ca.crt" && scheme == "http" {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		_, _ = w.Write(s.CA.CertificatePEM())
		return
	}
	host := r.Host
	if connectHost != "" {
		host = connectHost
		if !strings.EqualFold(stripPort(r.Host), stripPort(connectHost)) {
			http.Error(w, "CONNECT host and request host differ", http.StatusMisdirectedRequest)
			return
		}
	}
	if host == "" {
		http.Error(w, "missing Host", http.StatusBadRequest)
		return
	}
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(stripPort(host), r.TLS.ServerName) {
		http.Error(w, "TLS SNI and Host differ", http.StatusMisdirectedRequest)
		return
	}
	if scheme == "http" && r.URL.IsAbs() && r.URL.Scheme != "http" {
		http.Error(w, "invalid scheme", http.StatusBadRequest)
		return
	}
	if !s.allowedCapture(stripPort(host), r.RemoteAddr) {
		s.passthroughHTTP(w, r, scheme, host)
		return
	}
	if websocket.IsWebSocketUpgrade(r) {
		s.serveWebSocket(w, r, scheme, host)
		return
	}
	s.serveHTTP(w, r, scheme, host)
}

func (s *Server) allowedCapture(host, remote string) bool {
	if !s.targetAllowed(host) {
		return false
	}
	if !s.Config.AllowClients.Enabled() {
		return true
	}
	client, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(client)
	addr, ok := netip.AddrFromSlice(ip)
	return ok && s.Config.AllowClients.Match(addr)
}

func (s *Server) targetAllowed(host string) bool {
	if s.Config.AllowHosts.Match(host) {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if !s.Config.AllowHosts.HasIPs() || host == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := dnsserver.Resolver(s.Config.UpstreamDNS).LookupIPAddr(ctx, host)
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if ip, ok := netip.AddrFromSlice(address.IP); ok && s.Config.AllowHosts.MatchIP(ip) {
			return true
		}
	}
	return false
}

func (s *Server) passthroughHTTP(w http.ResponseWriter, r *http.Request, scheme, host string) {
	target := &url.URL{Scheme: scheme, Host: host}
	proxy := &httputil.ReverseProxy{
		Transport: s.transport,
		Rewrite: func(in *httputil.ProxyRequest) {
			in.SetURL(target)
			in.Out.Host = host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func stripPort(host string) string {
	if h, _, e := net.SplitHostPort(host); e == nil {
		return h
	}
	return host
}

type capped struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

type teeReadCloser struct {
	io.ReadCloser
	sink io.Writer
}

type replayReadCloser struct {
	io.Reader
	io.Closer
}

func readScriptBody(body *io.ReadCloser, limit int64) ([]byte, bool, error) {
	if *body == nil {
		return nil, true, nil
	}
	if limit <= 0 {
		limit = 10 << 20
	}
	original := *body
	data, err := io.ReadAll(io.LimitReader(original, limit+1))
	if err != nil || int64(len(data)) > limit {
		*body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(data), original), Closer: original}
		return nil, false, err
	}
	_ = original.Close()
	*body = io.NopCloser(bytes.NewReader(data))
	return data, true, nil
}

func (r *teeReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		_, _ = r.sink.Write(p[:n])
	}
	return n, err
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	remaining := c.limit - int64(c.buf.Len())
	if remaining <= 0 {
		if n > 0 {
			c.truncated = true
		}
		return n, nil
	}
	if int64(n) > remaining {
		_, _ = c.buf.Write(p[:remaining])
		c.truncated = true
		return n, nil
	}
	_, _ = c.buf.Write(p)
	return n, nil
}

type captureWriter struct {
	http.ResponseWriter
	status    int
	headers   http.Header
	body      capped
	onSSE     func(int, http.Header) (int64, *io.PipeWriter, <-chan struct{})
	sessionID int64
	ssePipe   *io.PipeWriter
	sseDone   <-chan struct{}
}

func (w *captureWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.headers = w.Header().Clone()
		if strings.HasPrefix(strings.ToLower(w.headers.Get("Content-Type")), "text/event-stream") && w.onSSE != nil {
			w.sessionID, w.ssePipe, w.sseDone = w.onSSE(code, w.headers)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *captureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.body.Write(p)
	n, err := w.ResponseWriter.Write(p)
	if n > 0 && w.ssePipe != nil {
		if _, pipeErr := w.ssePipe.Write(p[:n]); pipeErr != nil {
			_ = w.ssePipe.Close()
			w.ssePipe = nil
		}
	}
	return n, err
}
func (w *captureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, scheme, host string) {
	started := time.Now()
	requestURL := *r.URL
	requestURL.Scheme = scheme
	requestURL.Host = host
	var scriptRuns []store.ScriptRun
	if s.Scripts != nil {
		body, complete, err := readScriptBody(&r.Body, s.Config.BodyLimit)
		if err != nil {
			scriptRuns = append(scriptRuns, store.ScriptRun{Name: "script input", Phase: "request", Error: err.Error()})
		} else if !complete {
			scriptRuns = append(scriptRuns, store.ScriptRun{Name: "script input", Phase: "request", Error: "body exceeds script limit; request scripts skipped"})
		} else {
			exchange := scripts.Exchange{Method: r.Method, URL: requestURL.String(), Headers: r.Header.Clone(), Body: body}
			exchange, scriptRuns = s.Scripts.Apply(r.Context(), "request", exchange, s.Config.BodyLimit)
			modified := exchange.Body
			r.Body = io.NopCloser(bytes.NewReader(modified))
			r.ContentLength = int64(len(modified))
			r.TransferEncoding = nil
			r.Method = exchange.Method
			r.Header = exchange.Headers
			if updatedURL, parseErr := url.Parse(exchange.URL); parseErr == nil {
				r.URL.Path, r.URL.RawPath, r.URL.RawQuery = updatedURL.Path, updatedURL.RawPath, updatedURL.RawQuery
				requestURL = *updatedURL
			}
		}
	}
	reqBody := capped{limit: s.Config.BodyLimit}
	if r.Body != nil {
		r.Body = &teeReadCloser{ReadCloser: r.Body, sink: &reqBody}
	}
	cw := &captureWriter{ResponseWriter: w, body: capped{limit: s.Config.BodyLimit}}
	target := &url.URL{Scheme: scheme, Host: host}
	cw.onSSE = func(status int, headers http.Header) (int64, *io.PipeWriter, <-chan struct{}) {
		initial := &store.Session{Time: started, Method: r.Method, URL: requestURL.String(), Proto: r.Proto, Status: status, ClientAddr: r.RemoteAddr, RequestHeaders: r.Header.Clone(), ResponseHeaders: headers, ScriptRuns: scriptRuns}
		id, err := s.Store.Save(initial)
		if err != nil {
			if s.Log != nil {
				s.Log.Error("save SSE session", "error", err)
			}
			return 0, nil, nil
		}
		reader, writer := io.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer reader.Close()
			for event, parseErr := range sse.Read(reader, &sse.ReadConfig{MaxEventSize: 16 << 20}) {
				if parseErr != nil {
					if s.Log != nil {
						s.Log.Warn("parse SSE event", "error", parseErr)
					}
					break
				}
				captured := capped{limit: s.Config.FrameLimit}
				_, _ = captured.Write([]byte(event.Data))
				if err := s.Store.AddMessage(id, store.Message{Time: time.Now(), Protocol: "sse", Name: event.Type, EventID: event.LastEventID, Body: captured.buf.Bytes(), Truncated: captured.truncated}); err != nil && s.Log != nil {
					s.Log.Error("save SSE event", "error", err)
				}
			}
		}()
		return id, writer, done
	}
	var proxyErr string
	var transport http.RoundTripper = s.transport
	if s.Mocks != nil {
		transport = mock.Transport{Rules: s.Mocks, Base: s.transport}
	}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(in *httputil.ProxyRequest) { in.SetURL(target); in.Out.Host = host }, ModifyResponse: func(resp *http.Response) error {
		if s.Scripts == nil || strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
			return nil
		}
		body, complete, err := readScriptBody(&resp.Body, s.Config.BodyLimit)
		if err != nil {
			scriptRuns = append(scriptRuns, store.ScriptRun{Name: "script input", Phase: "response", Error: err.Error()})
			return nil
		}
		if !complete {
			scriptRuns = append(scriptRuns, store.ScriptRun{Name: "script input", Phase: "response", Error: "body exceeds script limit; response scripts skipped"})
			return nil
		}
		exchange := scripts.Exchange{Method: r.Method, URL: requestURL.String(), Status: resp.StatusCode, Headers: resp.Header.Clone(), Body: body}
		var runs []store.ScriptRun
		exchange, runs = s.Scripts.Apply(r.Context(), "response", exchange, s.Config.BodyLimit)
		scriptRuns = append(scriptRuns, runs...)
		modified := exchange.Body
		resp.Body = io.NopCloser(bytes.NewReader(modified))
		resp.ContentLength = int64(len(modified))
		resp.StatusCode = exchange.Status
		resp.Status = fmt.Sprintf("%d %s", exchange.Status, http.StatusText(exchange.Status))
		resp.Header = exchange.Headers
		resp.Header.Del("Content-Length")
		resp.Header.Set("Content-Length", fmt.Sprint(len(modified)))
		return nil
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
		proxyErr = e.Error()
		http.Error(w, "upstream request failed", http.StatusBadGateway)
	}}
	proxy.ServeHTTP(cw, r)
	v := &store.Session{Time: started, Duration: time.Since(started), Method: r.Method, URL: requestURL.String(), Proto: r.Proto, Status: cw.status, ClientAddr: r.RemoteAddr, RequestHeaders: r.Header.Clone(), ResponseHeaders: cw.headers, RequestBody: reqBody.buf.Bytes(), ResponseBody: cw.body.buf.Bytes(), RequestTruncated: reqBody.truncated, ResponseTruncated: cw.body.truncated, Error: proxyErr, ScriptRuns: scriptRuns}
	if cw.ssePipe != nil {
		_ = cw.ssePipe.Close()
	}
	if cw.sseDone != nil {
		<-cw.sseDone
	}
	var err error
	if cw.sessionID != 0 {
		err = s.Store.UpdateSession(cw.sessionID, v)
	} else {
		_, err = s.Store.Save(v)
	}
	if err != nil && s.Log != nil {
		s.Log.Error("save session", "error", err)
	}
}

func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request, scheme, host string) {
	started := time.Now()
	u := url.URL{Scheme: "ws", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	if scheme == "https" {
		u.Scheme = "wss"
	}
	headers := http.Header{}
	for k, vals := range r.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Upgrade") || strings.HasPrefix(strings.ToLower(k), "sec-websocket-") {
			continue
		}
		headers[k] = append([]string(nil), vals...)
	}
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second, NetDialContext: (&net.Dialer{Timeout: 10 * time.Second, Resolver: dnsserver.Resolver(s.Config.UpstreamDNS)}).DialContext, Subprotocols: websocket.Subprotocols(r), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.Config.UpstreamRootCAs, VerifyConnection: rejectCompromisedUpstream}}
	up, resp, err := dialer.DialContext(r.Context(), u.String(), headers)
	if err != nil {
		http.Error(w, "upstream WebSocket failed", http.StatusBadGateway)
		s.saveWSError(r, u.String(), err)
		return
	}
	defer up.Close()
	responseHeaders := http.Header{}
	if resp != nil {
		for k, vs := range resp.Header {
			switch http.CanonicalHeaderKey(k) {
			case "Connection", "Upgrade", "Sec-Websocket-Accept", "Sec-Websocket-Extensions", "Sec-Websocket-Protocol", "Content-Length", "Transfer-Encoding":
				continue
			}
			responseHeaders[k] = append([]string(nil), vs...)
		}
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, Subprotocols: []string{up.Subprotocol()}}
	down, err := upgrader.Upgrade(w, r, responseHeaders)
	if err != nil {
		return
	}
	defer down.Close()
	responseHeaders.Set("Connection", "Upgrade")
	responseHeaders.Set("Upgrade", "websocket")
	if proto := up.Subprotocol(); proto != "" {
		responseHeaders.Set("Sec-WebSocket-Protocol", proto)
	}
	v := &store.Session{Time: started, Duration: time.Since(started), Method: r.Method, URL: u.String(), Proto: r.Proto, Status: 101, ClientAddr: r.RemoteAddr, RequestHeaders: r.Header.Clone(), ResponseHeaders: responseHeaders}
	id, err := s.Store.Save(v)
	if err != nil {
		if s.Log != nil {
			s.Log.Error("save websocket", "error", err)
		}
		return
	}
	type result struct{ err error }
	done := make(chan result, 2)
	bridge := func(from, to *websocket.Conn, fromClient bool) {
		for {
			typ, reader, e := from.NextReader()
			if e != nil {
				done <- result{e}
				return
			}
			writer, e := to.NextWriter(typ)
			if e != nil {
				done <- result{e}
				return
			}
			captured := capped{limit: s.Config.FrameLimit}
			_, e = io.Copy(io.MultiWriter(writer, &captured), reader)
			closeErr := writer.Close()
			if e == nil {
				e = closeErr
			}
			_ = s.Store.AddMessage(id, store.Message{Time: time.Now(), FromClient: fromClient, Type: typ, Body: captured.buf.Bytes(), Truncated: captured.truncated})
			if e != nil {
				done <- result{e}
				return
			}
		}
	}
	go bridge(down, up, true)
	go bridge(up, down, false)
	<-done
	_ = down.Close()
	_ = up.Close()
	<-done
}

func (s *Server) saveWSError(r *http.Request, target string, err error) {
	_, _ = s.Store.Save(&store.Session{Time: time.Now(), Method: r.Method, URL: target, Proto: r.Proto, Status: 502, ClientAddr: r.RemoteAddr, RequestHeaders: r.Header.Clone(), Error: err.Error()})
}

func (s *Server) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Root())
	return pool
}
