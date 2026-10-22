package mock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lihongjie0209/liujian/internal/store"
)

type Config struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Method    string      `json:"method,omitempty"`
	URLRegex  string      `json:"url_regex,omitempty"`
	SessionID int64       `json:"session_id,omitempty"`
	File      string      `json:"file,omitempty"`
	Status    int         `json:"status,omitempty"`
	Headers   http.Header `json:"headers,omitempty"`
}

type entry struct {
	method, source string
	url            *regexp.Regexp
	status         int
	headers        http.Header
	body           []byte
}

type Rules struct{ entries []entry }

func Load(path string, db *store.Store) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if len(config.Rules) == 0 {
		return nil, errors.New("mock config has no rules")
	}
	result := &Rules{}
	for i, rule := range config.Rules {
		item, err := compile(rule, filepath.Dir(path), db)
		if err != nil {
			return nil, fmt.Errorf("mock rule %d: %w", i+1, err)
		}
		result.entries = append(result.entries, item)
	}
	return result, nil
}

func compile(rule Rule, dir string, db *store.Store) (entry, error) {
	if (rule.SessionID > 0) == (rule.File != "") {
		return entry{}, errors.New("set exactly one of session_id or file")
	}
	item := entry{method: strings.ToUpper(rule.Method), status: rule.Status, headers: rule.Headers.Clone()}
	if rule.SessionID > 0 {
		if db == nil {
			return item, errors.New("session store is required")
		}
		saved, err := db.Get(rule.SessionID)
		if err != nil {
			return item, err
		}
		if saved.ResponseTruncated || saved.Status < 100 || saved.Status > 599 || saved.Error != "" {
			return item, errors.New("recorded response is incomplete")
		}
		item.source = fmt.Sprintf("session %d", rule.SessionID)
		item.body = append([]byte(nil), saved.ResponseBody...)
		if item.status == 0 {
			item.status = saved.Status
		}
		if item.headers == nil {
			item.headers = saved.ResponseHeaders.Clone()
		}
		if item.method == "" {
			item.method = strings.ToUpper(saved.Method)
		}
		if rule.URLRegex == "" {
			rule.URLRegex = "^" + regexp.QuoteMeta(saved.URL) + "$"
		}
	} else {
		if rule.URLRegex == "" {
			return item, errors.New("file rule requires url_regex")
		}
		filename := rule.File
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(dir, filename)
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return item, err
		}
		item.source = filename
		item.body = data
		if item.status == 0 {
			item.status = http.StatusOK
		}
		if item.headers == nil {
			item.headers = make(http.Header)
		}
		if item.headers.Get("Content-Type") == "" {
			contentType := mime.TypeByExtension(filepath.Ext(filename))
			if contentType == "" {
				contentType = http.DetectContentType(data)
			}
			item.headers.Set("Content-Type", contentType)
		}
	}
	if item.status < 200 || item.status > 599 || item.status == http.StatusSwitchingProtocols {
		return item, fmt.Errorf("unsupported mock status %d", item.status)
	}
	pattern, err := regexp.Compile(rule.URLRegex)
	if err != nil {
		return item, err
	}
	item.url = pattern
	return item, nil
}

// Transport serves matching rules and delegates all other requests.
type Transport struct {
	Rules *Rules
	Base  http.RoundTripper
}

func (t Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.Rules != nil {
		for _, rule := range t.Rules.entries {
			if rule.method != "" && rule.method != request.Method || !rule.url.MatchString(request.URL.String()) {
				continue
			}
			if request.Body != nil {
				_, err := io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				if err != nil {
					return nil, err
				}
			}
			header := rule.headers.Clone()
			stripHeaders(header)
			body := append([]byte(nil), rule.body...)
			return &http.Response{StatusCode: rule.status, Status: fmt.Sprintf("%d %s", rule.status, http.StatusText(rule.status)), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
		}
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(request)
}

func stripHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Transfer-Encoding", "Content-Length", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Trailer", "Upgrade"} {
		header.Del(name)
	}
}
