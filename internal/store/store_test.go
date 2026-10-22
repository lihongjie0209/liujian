package store

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListQueryTypeAndBodyKeywords(t *testing.T) {
	db, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(`{"secret":"response needle"}`))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	items := []Session{
		{Time: time.Now(), Method: "POST", URL: "https://example.test/api/orders", RequestHeaders: http.Header{"X-Request": {"header needle"}}, ResponseHeaders: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, RequestBody: []byte(`{"request":"body needle"}`), ResponseBody: compressed.Bytes(), ScriptRuns: []ScriptRun{{Name: "decrypt", Phase: "response", Display: "decoded keyword"}}},
		{Time: time.Now(), Method: "GET", URL: "https://example.test/index.html", ResponseHeaders: http.Header{"Content-Type": {"text/html"}}, ResponseBody: []byte("page")},
	}
	for _, item := range items {
		if _, err := db.Save(&item); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		query Query
		want  string
	}{
		{"fetch", Query{Kind: "fetch"}, "/api/orders"},
		{"document", Query{Kind: "doc"}, "/index.html"},
		{"request body", Query{Request: "body needle"}, "/api/orders"},
		{"request header", Query{Request: "header needle"}, "/api/orders"},
		{"gzip response", Query{Response: "response needle"}, "/api/orders"},
		{"plain text", Query{Text: "response needle"}, "/api/orders"},
		{"script output", Query{Response: "decoded keyword"}, "/api/orders"},
		{"type and content", Query{Kind: "fetch", Response: "response needle"}, "/api/orders"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.ListQuery(500, tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || !strings.Contains(rows[0].URL, tc.want) {
				t.Fatalf("query %+v returned %+v", tc.query, rows)
			}
		})
	}
	rows, err := db.ListQuery(500, Query{Kind: "doc", Response: "response needle"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("unexpected combined filter result: %+v, %v", rows, err)
	}
}

func TestPersistAndExportHAR(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	id, err := db.Save(&Session{Time: start, Duration: 125 * time.Millisecond, Method: "POST", URL: "https://api.example.test/upload", Proto: "HTTP/2.0", Status: 201, RequestHeaders: http.Header{"Content-Type": []string{"text/plain"}}, ResponseHeaders: http.Header{"Content-Type": []string{"text/plain"}}, RequestBody: []byte("hello"), ResponseBody: []byte("done"), RequestTruncated: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AddMessage(id, Message{Time: start, FromClient: true, Type: 1, Body: []byte("frame")}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v, err := db.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.RequestBody) != "hello" || v.Duration != 125*time.Millisecond || len(v.Messages) != 1 || string(v.Messages[0].Body) != "frame" {
		t.Fatalf("restored session: %+v", v)
	}
	path := filepath.Join(dir, "capture.har")
	if err = db.ExportHAR(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Version string
			Entries []map[string]any
		}
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Log.Version != "1.2" || len(doc.Log.Entries) != 1 {
		t.Fatalf("HAR log: %+v", doc.Log)
	}
	if _, ok := doc.Log.Entries[0]["_webSocketMessages"]; !ok {
		t.Fatal("missing WebSocket HAR extension")
	}
	entry := doc.Log.Entries[0]
	timings := entry["timings"].(map[string]any)
	if entry["time"] != 125.0 || timings["send"] != 0.0 || timings["wait"] != 125.0 || timings["receive"] != 0.0 {
		t.Fatalf("invalid HAR timings: %+v", entry)
	}
}

func TestListQueryCombinesURLAndProtocol(t *testing.T) {
	db, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, session := range []Session{
		{Time: time.Now(), Method: "GET", URL: "https://api.example.test/orders", Proto: "HTTP/2.0", Status: 200, ClientAddr: "192.168.1.8:1234"},
		{Time: time.Now(), Method: "GET", URL: "https://api.example.test/events", Proto: "HTTP/1.1", Status: 200, ResponseHeaders: http.Header{"Content-Type": {"text/event-stream"}}},
		{Time: time.Now(), Method: "TLS", URL: "tls://api.example.test", Proto: "TLS", Error: "bad certificate"},
	} {
		if _, err := db.Save(&session); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		query Query
		want  string
	}{
		{Query{URL: "orders", Protocol: "https", Client: "192.168.1.8"}, "/orders"},
		{Query{Protocol: "sse"}, "/events"},
		{Query{Protocol: "tls"}, "tls://"},
		{Query{Protocol: "h2", Status: "200"}, "/orders"},
	} {
		rows, err := db.ListQuery(500, tc.query)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || !strings.Contains(rows[0].URL, tc.want) {
			t.Errorf("query %+v returned %+v", tc.query, rows)
		}
	}
}

func TestOpenMigratesOldSessions(t *testing.T) {
	dir := t.TempDir()
	old, err := sql.Open("sqlite", filepath.Join(dir, "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec("CREATE TABLE sessions (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, method TEXT, url TEXT, proto TEXT, status INTEGER, req_headers BLOB, resp_headers BLOB, req_body BLOB, resp_body BLOB, req_truncated INTEGER, resp_truncated INTEGER, error TEXT, size INTEGER NOT NULL)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, ts TEXT NOT NULL, from_client INTEGER, type INTEGER, body BLOB, truncated INTEGER)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec("INSERT INTO sessions(ts,method,url,proto,status,resp_headers,size) VALUES(?,?,?,?,?,?,?)", time.Now().Format(time.RFC3339Nano), "GET", "https://example.test/legacy.html", "HTTP/1.1", 200, []byte(`{"Content-Type":["text/html"]}`), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacy, err := db.ListQuery(10, Query{Kind: "doc"})
	if err != nil || len(legacy) != 1 || !strings.Contains(legacy[0].URL, "legacy.html") {
		t.Fatalf("legacy type migration: %+v, %v", legacy, err)
	}
	id, err := db.Save(&Session{Time: time.Now(), Duration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(id, Message{Time: time.Now(), Protocol: "sse", Name: "update", EventID: "42", Body: []byte(`{"ok":true}`)}); err != nil {
		t.Fatal(err)
	}
	session, err := db.Get(id)
	if err != nil || len(session.Messages) != 1 || session.Messages[0].Protocol != "sse" {
		t.Fatalf("migrated SSE message: session=%+v err=%v", session, err)
	}
	entry := harEntry(session)
	if _, ok := entry["_sseEvents"]; !ok {
		t.Fatal("missing SSE HAR extension")
	}
}

func TestUpdateStreamingSessionKeepsEvents(t *testing.T) {
	db, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	started := time.Now()
	id, err := db.Save(&Session{Time: started, URL: "http://example.test/events", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(id, Message{Time: started, Protocol: "sse", Name: "update", Body: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateSession(id, &Session{Duration: time.Second, Status: 200, ResponseBody: []byte("data: first\n\n")}); err != nil {
		t.Fatal(err)
	}
	got, err := db.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Duration != time.Second || string(got.ResponseBody) != "data: first\n\n" || len(got.Messages) != 1 || string(got.Messages[0].Body) != "first" {
		t.Fatalf("completed streaming session: %+v", got)
	}
}
