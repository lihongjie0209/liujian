package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lihongjie0209/liujian/internal/store"
)

const maxResponseBody = 10 << 20

// Request rebuilds a captured HTTP request for replay.
func Request(ctx context.Context, saved *store.Session) (*http.Request, error) {
	if saved == nil || saved.RequestTruncated || saved.Status == http.StatusSwitchingProtocols {
		return nil, errors.New("session cannot be replayed: incomplete or non-HTTP request")
	}
	u, err := url.Parse(saved.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("session has invalid HTTP URL %q", saved.URL)
	}
	if saved.Method == "" {
		return nil, errors.New("session has no request method")
	}
	req, err := http.NewRequestWithContext(ctx, saved.Method, saved.URL, bytes.NewReader(saved.RequestBody))
	if err != nil {
		return nil, err
	}
	req.Header = saved.RequestHeaders.Clone()
	removeHopHeaders(req.Header)
	req.Header.Del("Content-Length")
	return req, nil
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

// Send replays one saved request and records its response as a new session.
func Send(ctx context.Context, db *store.Store, id int64, timeout time.Duration) (*store.Session, error) {
	saved, err := db.Get(id)
	if err != nil {
		return nil, err
	}
	req, err := Request(ctx, saved)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	started := time.Now()
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("replay session %d: %w", id, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	truncated := len(body) > maxResponseBody
	if truncated {
		body = body[:maxResponseBody]
	}
	v := &store.Session{Time: started, Duration: time.Since(started), Method: req.Method, URL: req.URL.String(), Proto: response.Proto, Status: response.StatusCode, RequestHeaders: req.Header.Clone(), ResponseHeaders: response.Header.Clone(), RequestBody: append([]byte(nil), saved.RequestBody...), ResponseBody: body, ResponseTruncated: truncated, ClientAddr: fmt.Sprintf("replay:%d", id)}
	v.ID, err = db.Save(v)
	return v, err
}

// Curl returns a POSIX shell command for a captured request.
func Curl(saved *store.Session) (string, error) {
	req, err := Request(context.Background(), saved)
	if err != nil {
		return "", err
	}
	var parts []string
	parts = append(parts, "curl", "--request", quote(req.Method), "--url", quote(req.URL.String()))
	var names []string
	for name := range req.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range req.Header.Values(name) {
			parts = append(parts, "--header", quote(name+": "+value))
		}
	}
	if len(saved.RequestBody) == 0 {
		return strings.Join(parts, " "), nil
	}
	// Hex plus xxd avoids printing arbitrary binary as terminal control bytes.
	return "printf '%s' " + quote(fmt.Sprintf("%x", saved.RequestBody)) + " | xxd -r -p | " + strings.Join(append(parts, "--data-binary", "@-"), " "), nil
}

func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
