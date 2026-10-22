package mock

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/store"
)

func TestRecordedAndLocalFileMock(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: "https://api.test/saved", Status: 202, ResponseHeaders: http.Header{"Content-Type": {"application/json"}}, ResponseBody: []byte(`{"ok":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.txt"), []byte("local"), 0600); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(Config{Rules: []Rule{{SessionID: id}, {URLRegex: "^https://api.test/local$", File: "local.txt"}}})
	path := filepath.Join(dir, "mocks.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(path, db)
	if err != nil {
		t.Fatal(err)
	}
	transport := Transport{Rules: rules, Base: http.DefaultTransport}
	for _, tc := range []struct {
		url    string
		status int
		body   string
	}{{"https://api.test/saved", 202, `{"ok":true}`}, {"https://api.test/local", 200, "local"}} {
		req, _ := http.NewRequest("GET", tc.url, strings.NewReader("request body"))
		response, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != tc.status || string(body) != tc.body {
			t.Fatalf("%s: %d %q", tc.url, response.StatusCode, body)
		}
	}
}
