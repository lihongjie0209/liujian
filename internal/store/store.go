package store

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

type Session struct {
	ID                                  int64
	Time                                time.Time
	Duration                            time.Duration
	Method, URL, Proto                  string
	Status                              int
	RequestHeaders, ResponseHeaders     http.Header
	RequestBody, ResponseBody           []byte
	ResponseBytes                       int64
	RequestTruncated, ResponseTruncated bool
	Error                               string
	ClientAddr                          string
	ErrorCount                          int
	Kind                                string
	Messages                            []Message
	ScriptRuns                          []ScriptRun
}

type ScriptRun struct {
	Name     string        `json:"name"`
	Phase    string        `json:"phase"`
	Display  string        `json:"display,omitempty"`
	Console  string        `json:"console,omitempty"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

type Message struct {
	Time       time.Time
	Protocol   string
	Name       string
	EventID    string
	FromClient bool
	Type       int
	Body       []byte
	Truncated  bool
}

type StreamMessage struct {
	ID        int64
	SessionID int64
	Message
}

type Store struct {
	db       *sql.DB
	maxBytes int64
}

func Open(dir string, maxBytes int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "sessions.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, query := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000",
		"CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, duration_ns INTEGER NOT NULL DEFAULT 0, method TEXT, url TEXT, proto TEXT, status INTEGER, req_headers BLOB, resp_headers BLOB, req_body BLOB, resp_body BLOB, req_search BLOB, resp_search BLOB, req_display BLOB, resp_display BLOB, kind TEXT NOT NULL DEFAULT 'other', req_truncated INTEGER, resp_truncated INTEGER, error TEXT, client_addr TEXT NOT NULL DEFAULT '', error_count INTEGER NOT NULL DEFAULT 0, script_runs BLOB, size INTEGER NOT NULL)",
		"CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, ts TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'websocket', name TEXT NOT NULL DEFAULT '', event_id TEXT NOT NULL DEFAULT '', from_client INTEGER, type INTEGER, body BLOB, truncated INTEGER)",
		"CREATE INDEX IF NOT EXISTS sessions_ts ON sessions(ts)",
	} {
		if _, err = db.Exec(query); err != nil {
			db.Close()
			return nil, err
		}
	}
	columns, err := db.Query("PRAGMA table_info(sessions)")
	if err != nil {
		db.Close()
		return nil, err
	}
	columnsPresent := make(map[string]bool)
	for columns.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue sql.NullString
		if err = columns.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			columns.Close()
			db.Close()
			return nil, err
		}
		columnsPresent[name] = true
	}
	err = columns.Err()
	columns.Close()
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, column := range []struct{ name, definition string }{
		{"duration_ns", "INTEGER NOT NULL DEFAULT 0"},
		{"client_addr", "TEXT NOT NULL DEFAULT ''"},
		{"error_count", "INTEGER NOT NULL DEFAULT 0"},
		{"script_runs", "BLOB"},
		{"req_search", "BLOB"},
		{"resp_search", "BLOB"},
		{"req_display", "BLOB"},
		{"resp_display", "BLOB"},
		{"kind", "TEXT NOT NULL DEFAULT 'other'"},
	} {
		if columnsPresent[column.name] {
			continue
		}
		if _, err = db.Exec("ALTER TABLE sessions ADD COLUMN " + column.name + " " + column.definition); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = addMessageColumns(db); err != nil {
		db.Close()
		return nil, err
	}
	if !columnsPresent["kind"] {
		if err := backfillKinds(db); err != nil {
			db.Close()
			return nil, err
		}
	}
	_ = os.Chmod(path, 0600)
	return &Store{db: db, maxBytes: maxBytes}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func addMessageColumns(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(messages)")
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue sql.NullString
		if err = rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{
		{"protocol", "TEXT NOT NULL DEFAULT 'websocket'"},
		{"name", "TEXT NOT NULL DEFAULT ''"},
		{"event_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		if !columns[column.name] {
			if _, err = db.Exec("ALTER TABLE messages ADD COLUMN " + column.name + " " + column.definition); err != nil {
				return err
			}
		}
	}
	return nil
}

func ResourceKind(v Session) string {
	if v.Proto == "TLS" {
		return "tls"
	}
	if v.Status == http.StatusSwitchingProtocols || strings.EqualFold(v.ResponseHeaders.Get("Upgrade"), "websocket") {
		return "ws"
	}
	contentType, _, _ := mime.ParseMediaType(v.ResponseHeaders.Get("Content-Type"))
	contentType = strings.ToLower(contentType)
	u, _ := url.Parse(v.URL)
	ext := strings.ToLower(filepath.Ext(u.Path))
	switch {
	case contentType == "text/event-stream":
		return "sse"
	case contentType == "text/html" || contentType == "application/xhtml+xml" || ext == ".html" || ext == ".htm":
		return "doc"
	case contentType == "text/css" || ext == ".css":
		return "css"
	case strings.Contains(contentType, "javascript") || ext == ".js" || ext == ".mjs":
		return "js"
	case strings.HasPrefix(contentType, "image/") || ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".svg" || ext == ".webp" || ext == ".ico":
		return "img"
	case strings.HasPrefix(contentType, "audio/") || strings.HasPrefix(contentType, "video/") || ext == ".mp4" || ext == ".mp3" || ext == ".webm":
		return "media"
	case strings.HasPrefix(contentType, "font/") || strings.Contains(contentType, "font-") || ext == ".woff" || ext == ".woff2" || ext == ".ttf" || ext == ".otf":
		return "font"
	case strings.Contains(contentType, "manifest") || ext == ".webmanifest":
		return "manifest"
	case contentType == "application/wasm" || ext == ".wasm":
		return "wasm"
	case strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") || strings.HasPrefix(contentType, "text/plain") || strings.HasPrefix(u.Path, "/api/"):
		return "fetch"
	default:
		return "other"
	}
}

func decodedSearchBody(body []byte, headers http.Header) []byte {
	if !strings.EqualFold(strings.TrimSpace(headers.Get("Content-Encoding")), "gzip") || len(body) == 0 {
		return nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	defer reader.Close()
	const maxDecoded = 10 << 20
	decoded, err := io.ReadAll(io.LimitReader(reader, maxDecoded+1))
	if err != nil || len(decoded) > maxDecoded {
		return nil
	}
	return decoded
}

func scriptDisplay(runs []ScriptRun, phase string) []byte {
	var b strings.Builder
	for _, run := range runs {
		if run.Phase != phase {
			continue
		}
		b.WriteString(run.Display)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func bodySearchSQL(prefix string) string {
	return "(instr(lower(CAST(" + prefix + "_headers AS TEXT)),lower(?))>0 OR instr(lower(CAST(" + prefix + "_body AS TEXT)),lower(?))>0 OR instr(lower(CAST(" + prefix + "_search AS TEXT)),lower(?))>0 OR instr(lower(CAST(" + prefix + "_display AS TEXT)),lower(?))>0)"
}

func bodySearchArgs(term string) []any { return []any{term, term, term, term} }

func backfillKinds(db *sql.DB) error {
	type item struct {
		id   int64
		kind string
	}
	var lastID int64
	for {
		rows, err := db.Query("SELECT id,COALESCE(url,''),COALESCE(proto,''),COALESCE(status,0),resp_headers FROM sessions WHERE id>? ORDER BY id LIMIT 500", lastID)
		if err != nil {
			return err
		}
		var items []item
		for rows.Next() {
			var v Session
			var headers []byte
			if err := rows.Scan(&v.ID, &v.URL, &v.Proto, &v.Status, &headers); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(headers, &v.ResponseHeaders)
			items = append(items, item{v.ID, ResourceKind(v)})
			lastID = v.ID
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, item := range items {
			if _, err := db.Exec("UPDATE sessions SET kind=? WHERE id=?", item.kind, item.id); err != nil {
				return err
			}
		}
		if len(items) < 500 {
			return nil
		}
	}
}

func (s *Store) Save(v *Session) (int64, error) {
	req, _ := json.Marshal(v.RequestHeaders)
	resp, _ := json.Marshal(v.ResponseHeaders)
	runs, _ := json.Marshal(v.ScriptRuns)
	reqSearch := decodedSearchBody(v.RequestBody, v.RequestHeaders)
	respSearch := decodedSearchBody(v.ResponseBody, v.ResponseHeaders)
	reqDisplay, respDisplay := scriptDisplay(v.ScriptRuns, "request"), scriptDisplay(v.ScriptRuns, "response")
	size := len(req) + len(resp) + len(runs) + len(reqSearch) + len(respSearch) + len(reqDisplay) + len(respDisplay) + len(v.RequestBody) + len(v.ResponseBody) + len(v.URL) + len(v.Error) + len(v.ClientAddr) + 256
	r, err := s.db.Exec("INSERT INTO sessions(ts,duration_ns,method,url,proto,status,req_headers,resp_headers,req_body,resp_body,req_search,resp_search,req_display,resp_display,kind,req_truncated,resp_truncated,error,client_addr,error_count,script_runs,size) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		v.Time.Format(time.RFC3339Nano), int64(v.Duration), v.Method, v.URL, v.Proto, v.Status, req, resp, v.RequestBody, v.ResponseBody, reqSearch, respSearch, reqDisplay, respDisplay, ResourceKind(*v), v.RequestTruncated, v.ResponseTruncated, v.Error, v.ClientAddr, v.ErrorCount, runs, size)
	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	s.prune()
	return id, nil
}

// IncrementErrorCount groups repeated failures into an existing session.
func (s *Store) IncrementErrorCount(id int64) (bool, error) {
	result, err := s.db.Exec("UPDATE sessions SET error_count=error_count+1 WHERE id=?", id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

// UpdateSession completes an SSE session that was stored when response headers arrived.
func (s *Store) UpdateSession(id int64, v *Session) error {
	req, _ := json.Marshal(v.RequestHeaders)
	resp, _ := json.Marshal(v.ResponseHeaders)
	runs, _ := json.Marshal(v.ScriptRuns)
	reqSearch := decodedSearchBody(v.RequestBody, v.RequestHeaders)
	respSearch := decodedSearchBody(v.ResponseBody, v.ResponseHeaders)
	reqDisplay, respDisplay := scriptDisplay(v.ScriptRuns, "request"), scriptDisplay(v.ScriptRuns, "response")
	size := len(req) + len(resp) + len(runs) + len(reqSearch) + len(respSearch) + len(reqDisplay) + len(respDisplay) + len(v.RequestBody) + len(v.ResponseBody) + len(v.URL) + len(v.Error) + len(v.ClientAddr) + 256
	_, err := s.db.Exec("UPDATE sessions SET duration_ns=?,status=?,req_headers=?,resp_headers=?,req_body=?,resp_body=?,req_search=?,resp_search=?,req_display=?,resp_display=?,kind=?,req_truncated=?,resp_truncated=?,error=?,client_addr=?,script_runs=?,size=? + (SELECT COALESCE(SUM(length(body)+64),0) FROM messages WHERE session_id=?) WHERE id=?",
		int64(v.Duration), v.Status, req, resp, v.RequestBody, v.ResponseBody, reqSearch, respSearch, reqDisplay, respDisplay, ResourceKind(*v), v.RequestTruncated, v.ResponseTruncated, v.Error, v.ClientAddr, runs, size, id, id)
	if err == nil {
		s.prune()
	}
	return err
}

func (s *Store) AddMessage(sessionID int64, m Message) error {
	if m.Protocol == "" {
		m.Protocol = "websocket"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO messages(session_id,ts,protocol,name,event_id,from_client,type,body,truncated) VALUES(?,?,?,?,?,?,?,?,?)", sessionID, m.Time.Format(time.RFC3339Nano), m.Protocol, m.Name, m.EventID, m.FromClient, m.Type, m.Body, m.Truncated); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE sessions SET size=size+? WHERE id=?", len(m.Body)+64, sessionID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.prune()
	return nil
}

func (s *Store) List(limit int, filter string) ([]Session, error) {
	return s.ListQuery(limit, Query{Text: filter})
}

type Query struct {
	Text, URL, Protocol, Method, Status, Client, Kind, Request, Response string
}

func (s *Store) ListQuery(limit int, filter Query) ([]Session, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := "SELECT id,ts,COALESCE(method,''),COALESCE(url,''),COALESCE(proto,''),COALESCE(status,0),COALESCE(error,''),client_addr,error_count,duration_ns,resp_headers,COALESCE(length(resp_body),0),COALESCE(resp_truncated,0),kind FROM sessions"
	var args []any
	var clauses []string
	if filter.Text != "" {
		clauses = append(clauses, "(instr(lower(url),lower(?))>0 OR instr(lower(method),lower(?))>0 OR instr(CAST(status AS TEXT),?)>0 OR instr(lower(error),lower(?))>0 OR "+bodySearchSQL("req")+" OR "+bodySearchSQL("resp")+")")
		args = append(args, filter.Text, filter.Text, filter.Text, filter.Text)
		args = append(args, bodySearchArgs(filter.Text)...)
		args = append(args, bodySearchArgs(filter.Text)...)
	}
	if filter.Request != "" {
		clauses = append(clauses, "(instr(lower(url),lower(?))>0 OR "+bodySearchSQL("req")+")")
		args = append(args, filter.Request)
		args = append(args, bodySearchArgs(filter.Request)...)
	}
	if filter.Response != "" {
		clauses = append(clauses, "(instr(CAST(status AS TEXT),?)>0 OR "+bodySearchSQL("resp")+")")
		args = append(args, filter.Response)
		args = append(args, bodySearchArgs(filter.Response)...)
	}
	if filter.Kind != "" {
		clauses = append(clauses, "kind=?")
		args = append(args, filter.Kind)
	}
	if filter.URL != "" {
		clauses = append(clauses, "instr(lower(url),lower(?))>0")
		args = append(args, filter.URL)
	}
	if filter.Method != "" {
		clauses = append(clauses, "lower(method)=lower(?)")
		args = append(args, filter.Method)
	}
	if filter.Status != "" {
		clauses = append(clauses, "instr(CAST(status AS TEXT),?)>0")
		args = append(args, filter.Status)
	}
	if filter.Client != "" {
		clauses = append(clauses, "instr(lower(client_addr),lower(?))>0")
		args = append(args, filter.Client)
	}
	switch strings.ToLower(filter.Protocol) {
	case "http", "https", "ws", "wss":
		protocol := strings.ToLower(filter.Protocol)
		clauses = append(clauses, "lower(url) LIKE ?")
		args = append(args, protocol+"://%")
	case "websocket":
		clauses = append(clauses, "status=101")
	case "sse":
		clauses = append(clauses, "instr(lower(resp_headers),'text/event-stream')>0")
	case "h2", "http2":
		clauses = append(clauses, "proto='HTTP/2.0'")
	case "http1":
		clauses = append(clauses, "proto='HTTP/1.1'")
	case "":
	default:
		clauses = append(clauses, "instr(lower(proto),lower(?))>0")
		args = append(args, filter.Protocol)
	}
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Session
	for rows.Next() {
		var v Session
		var stamp string
		var durationNS int64
		var responseHeaders []byte
		if err = rows.Scan(&v.ID, &stamp, &v.Method, &v.URL, &v.Proto, &v.Status, &v.Error, &v.ClientAddr, &v.ErrorCount, &durationNS, &responseHeaders, &v.ResponseBytes, &v.ResponseTruncated, &v.Kind); err != nil {
			return nil, err
		}
		v.Time, _ = time.Parse(time.RFC3339Nano, stamp)
		v.Duration = time.Duration(durationNS)
		_ = json.Unmarshal(responseHeaders, &v.ResponseHeaders)
		result = append(result, v)
	}
	return result, rows.Err()
}

// IDsAfter returns new sessions in capture order for streaming consumers.
func (s *Store) IDsAfter(last int64, limit int) ([]int64, error) {
	if limit < 1 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.Query("SELECT id FROM sessions WHERE id>? ORDER BY id LIMIT ?", last, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) LatestIDs() (sessionID, messageID int64, err error) {
	err = s.db.QueryRow("SELECT COALESCE(MAX(id),0) FROM sessions").Scan(&sessionID)
	if err != nil {
		return
	}
	err = s.db.QueryRow("SELECT COALESCE(MAX(id),0) FROM messages").Scan(&messageID)
	return
}

func (s *Store) MessagesAfter(last int64, limit int) ([]StreamMessage, error) {
	if limit < 1 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.Query("SELECT id,session_id,ts,protocol,name,event_id,from_client,type,body,truncated FROM messages WHERE id>? ORDER BY id LIMIT ?", last, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []StreamMessage
	for rows.Next() {
		var item StreamMessage
		var stamp string
		if err := rows.Scan(&item.ID, &item.SessionID, &stamp, &item.Protocol, &item.Name, &item.EventID, &item.FromClient, &item.Type, &item.Body, &item.Truncated); err != nil {
			return nil, err
		}
		item.Time, _ = time.Parse(time.RFC3339Nano, stamp)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) Get(id int64) (*Session, error) {
	row := s.db.QueryRow("SELECT id,ts,duration_ns,COALESCE(method,''),COALESCE(url,''),COALESCE(proto,''),COALESCE(status,0),req_headers,resp_headers,req_body,resp_body,COALESCE(req_truncated,0),COALESCE(resp_truncated,0),COALESCE(error,''),client_addr,error_count,script_runs FROM sessions WHERE id=?", id)
	var v Session
	var stamp string
	var durationNS int64
	var req, resp, runs []byte
	if err := row.Scan(&v.ID, &stamp, &durationNS, &v.Method, &v.URL, &v.Proto, &v.Status, &req, &resp, &v.RequestBody, &v.ResponseBody, &v.RequestTruncated, &v.ResponseTruncated, &v.Error, &v.ClientAddr, &v.ErrorCount, &runs); err != nil {
		return nil, err
	}
	v.Time, _ = time.Parse(time.RFC3339Nano, stamp)
	v.Duration = time.Duration(durationNS)
	v.ResponseBytes = int64(len(v.ResponseBody))
	_ = json.Unmarshal(req, &v.RequestHeaders)
	_ = json.Unmarshal(resp, &v.ResponseHeaders)
	_ = json.Unmarshal(runs, &v.ScriptRuns)
	rows, err := s.db.Query("SELECT ts,protocol,name,event_id,from_client,type,body,truncated FROM messages WHERE session_id=? ORDER BY id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m Message
		var t string
		if err = rows.Scan(&t, &m.Protocol, &m.Name, &m.EventID, &m.FromClient, &m.Type, &m.Body, &m.Truncated); err != nil {
			return nil, err
		}
		m.Time, _ = time.Parse(time.RFC3339Nano, t)
		v.Messages = append(v.Messages, m)
	}
	return &v, rows.Err()
}

func (s *Store) ExportHAR(path string) error {
	rows, err := s.db.Query("SELECT id FROM sessions ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	entries := make([]any, 0, len(ids))
	for _, id := range ids {
		v, e := s.Get(id)
		if e != nil {
			return e
		}
		entries = append(entries, harEntry(v))
	}
	doc := map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "liujian", "version": "0.1.0"}, "entries": entries}}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func harEntry(v *Session) map[string]any {
	reqHeaders := harHeaders(v.RequestHeaders)
	respHeaders := harHeaders(v.ResponseHeaders)
	req := map[string]any{"method": v.Method, "url": v.URL, "httpVersion": v.Proto, "headers": reqHeaders, "queryString": harQuery(v.URL), "cookies": harRequestCookies(v.RequestHeaders), "headersSize": -1, "bodySize": len(v.RequestBody)}
	if len(v.RequestBody) > 0 {
		req["postData"] = harContent(v.RequestBody, v.RequestHeaders.Get("Content-Type"))
	}
	resp := map[string]any{"status": v.Status, "statusText": http.StatusText(v.Status), "httpVersion": v.Proto, "headers": respHeaders, "cookies": harResponseCookies(v.ResponseHeaders), "content": harContent(v.ResponseBody, v.ResponseHeaders.Get("Content-Type")), "redirectURL": v.ResponseHeaders.Get("Location"), "headersSize": -1, "bodySize": len(v.ResponseBody)}
	durationMS := max(0, float64(v.Duration)/float64(time.Millisecond))
	entry := map[string]any{"startedDateTime": v.Time.Format(time.RFC3339Nano), "time": durationMS, "request": req, "response": resp, "cache": map[string]any{}, "timings": map[string]float64{"send": 0, "wait": durationMS, "receive": 0}, "_timingApproximate": true, "_truncated": v.RequestTruncated || v.ResponseTruncated}
	if v.Error != "" {
		entry["_error"] = v.Error
		if v.ErrorCount > 0 {
			entry["_errorCount"] = v.ErrorCount
		}
		if v.ClientAddr != "" {
			entry["_clientAddress"] = v.ClientAddr
		}
	}
	if len(v.ScriptRuns) > 0 {
		entry["_scripts"] = v.ScriptRuns
	}
	var wsMessages, sseEvents []any
	for _, m := range v.Messages {
		body := harContent(m.Body, "")
		if m.Protocol == "sse" {
			sseEvents = append(sseEvents, map[string]any{"time": m.Time.Format(time.RFC3339Nano), "id": m.EventID, "event": m.Name, "content": body, "truncated": m.Truncated})
		} else {
			wsMessages = append(wsMessages, map[string]any{"time": m.Time.Format(time.RFC3339Nano), "fromClient": m.FromClient, "type": m.Type, "content": body, "truncated": m.Truncated})
		}
	}
	if len(wsMessages) > 0 {
		entry["_webSocketMessages"] = wsMessages
	}
	if len(sseEvents) > 0 {
		entry["_sseEvents"] = sseEvents
	}
	return entry
}

func harHeaders(h http.Header) []map[string]string {
	out := make([]map[string]string, 0)
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, map[string]string{"name": k, "value": v})
		}
	}
	return out
}
func harQuery(raw string) []map[string]string {
	out := make([]map[string]string, 0)
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	for name, values := range u.Query() {
		for _, value := range values {
			out = append(out, map[string]string{"name": name, "value": value})
		}
	}
	return out
}
func harRequestCookies(h http.Header) []map[string]string {
	out := make([]map[string]string, 0)
	r := &http.Request{Header: h}
	for _, c := range r.Cookies() {
		out = append(out, map[string]string{"name": c.Name, "value": c.Value})
	}
	return out
}
func harResponseCookies(h http.Header) []map[string]string {
	out := make([]map[string]string, 0)
	r := &http.Response{Header: h}
	for _, c := range r.Cookies() {
		out = append(out, map[string]string{"name": c.Name, "value": c.Value})
	}
	return out
}
func harContent(body []byte, mime string) map[string]any {
	if mime == "" {
		mime = http.DetectContentType(body)
	}
	c := map[string]any{"size": len(body), "mimeType": mime}
	if utf8.Valid(body) && !strings.Contains(mime, "octet-stream") {
		c["text"] = string(body)
	} else {
		c["text"] = base64.StdEncoding.EncodeToString(body)
		c["encoding"] = "base64"
	}
	return c
}

func (s *Store) prune() {
	if s.maxBytes <= 0 {
		return
	}
	var total int64
	if err := s.db.QueryRow("SELECT COALESCE(SUM(size),0) FROM sessions").Scan(&total); err != nil {
		return
	}
	for total > s.maxBytes {
		var id, size int64
		if err := s.db.QueryRow("SELECT id,size FROM sessions ORDER BY id LIMIT 1").Scan(&id, &size); err != nil {
			return
		}
		if _, err := s.db.Exec("DELETE FROM sessions WHERE id=?", id); err != nil {
			return
		}
		total -= size
	}
}

func (v Session) Summary() string {
	return fmt.Sprintf("%d %s %s %d %s", v.ID, v.Time.Format("15:04:05"), v.Method, v.Status, v.URL)
}
