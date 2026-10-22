package store

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSharedFilterMatchesDatabaseAndSession(t *testing.T) {
	db, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, item := range []Session{
		{Time: time.Now(), Method: "POST", URL: "https://api.test/submit", Status: 201, ClientAddr: "192.168.1.8:1234", RequestHeaders: http.Header{"X-Token": {"abc"}}, RequestBody: []byte(`{"name":"Alice"}`), ResponseBody: []byte("saved")},
		{Time: time.Now(), Method: "GET", URL: "https://api.test/health", Status: 200},
		{Time: time.Now(), Method: "GET", URL: "http://static.test/app.js", Status: 404},
	} {
		if _, err := db.Save(&item); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		expr string
		want int
	}{
		{"method:POST req:Alice status:2xx", 1},
		{"(url:/submit | url:/health) & !status:404", 2},
		{"!req:Alice", 2},
		{"proto:https & (status:201 | status:404)", 1},
		{"status:2xx | url:/app.js", 3},
		{"status:2xx & url:/app.js", 0},
		{"client:192.168.1.8 & req:abc", 1},
		{"status:404", 1},
	} {
		filter, err := ParseFilter(tc.expr)
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		rows, err := db.ListFiltered(100, filter)
		if err != nil || len(rows) != tc.want {
			t.Fatalf("%s: got %d rows, want %d: %v", tc.expr, len(rows), tc.want, err)
		}
		for _, row := range rows {
			full, err := db.Get(row.ID)
			if err != nil || !filter.Match(full) {
				t.Fatalf("%s: SQL and in-memory match differ for %d: %v", tc.expr, row.ID, err)
			}
		}
	}
	filter, _ := ParseFilter("method:POST")
	path := filepath.Join(t.TempDir(), "filtered.har")
	if err := db.ExportHARFiltered(path, filter); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Log.Entries) != 1 {
		t.Fatalf("filtered HAR has %d entries: %v", len(doc.Log.Entries), err)
	}
}

func TestFilterRejectsMalformedExpression(t *testing.T) {
	for _, input := range []string{"(url:/api", "url:/api &", "url:\"unfinished"} {
		if _, err := ParseFilter(input); err == nil {
			t.Fatalf("accepted malformed filter %q", input)
		}
	}
}
