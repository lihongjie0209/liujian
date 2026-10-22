package capture

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lihongjie0209/liujian/internal/store"
)

const tlsErrorWindow = 10 * time.Second

type recentTLSError struct {
	id    int64
	first time.Time
}

type httpErrorWriter struct{ server *Server }

func (w httpErrorWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		line := strings.TrimSpace(string(p))
		_, rest, _ := strings.Cut(line, "TLS handshake error from ")
		remote, reason, ok := strings.Cut(rest, ": ")
		if !ok {
			remote, reason = "", line
		}
		name, _ := w.server.tlsNames.LoadAndDelete(remote)
		serverName, _ := name.(string)
		w.server.recordTLSFailure(serverName, remote, reason)
		return len(p), nil
	}
	if w.server.Log != nil {
		w.server.Log.Warn("HTTP server", "message", strings.TrimSpace(string(p)))
	}
	return len(p), nil
}

func (s *Server) rememberTLSName(hello *tls.ClientHelloInfo) {
	if hello.Conn != nil && hello.ServerName != "" {
		s.tlsNames.Store(hello.Conn.RemoteAddr().String(), hello.ServerName)
	}
}

func (s *Server) clearTLSName(conn net.Conn, state http.ConnState) {
	if state == http.StateActive || state == http.StateClosed {
		s.tlsNames.Delete(conn.RemoteAddr().String())
	}
}

func (s *Server) recordTLSFailure(serverName, remote, reason string) {
	if !s.allowedCapture(serverName, remote) {
		return
	}
	s.tlsFailures.Add(1)
	if s.Store == nil {
		return
	}
	client := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		client = host
	}
	key := client + "\x00" + serverName + "\x00" + reason
	now := time.Now()
	s.tlsErrorsMu.Lock()
	defer s.tlsErrorsMu.Unlock()
	if previous, ok := s.tlsRecent[key]; ok && now.Sub(previous.first) < tlsErrorWindow {
		if updated, err := s.Store.IncrementErrorCount(previous.id); err == nil && updated {
			return
		}
	}
	target := serverName
	if target == "" {
		target = "unknown"
	}
	entry := &store.Session{
		Time: now, Method: "TLS", URL: (&url.URL{Scheme: "tls", Host: target}).String(),
		Proto: "TLS", ClientAddr: remote, Error: reason, ErrorCount: 1,
	}
	id, err := s.Store.Save(entry)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("save TLS failure", "error", err)
		}
		return
	}
	if len(s.tlsRecent) >= 1024 {
		clear(s.tlsRecent)
	}
	if s.tlsRecent == nil {
		s.tlsRecent = make(map[string]recentTLSError)
	}
	s.tlsRecent[key] = recentTLSError{id: id, first: now}
}
