package capture

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/mock"
	"github.com/lihongjie0209/liujian/internal/store"
)

func TestMockResponseUsesCapturePipeline(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(500)
	}))
	defer upstream.Close()
	id, err := db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: upstream.URL + "/mocked", Status: 202, ResponseBody: []byte("mock body")})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data, _ := json.Marshal(mock.Config{Rules: []mock.Rule{{SessionID: id}}})
	path := filepath.Join(dir, "mocks.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := mock.Load(path, db)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: db, Mocks: rules, Config: Config{BodyLimit: 1024}, transport: &http.Transport{Proxy: nil}}
	request := httptest.NewRequest("GET", upstream.URL+"/mocked", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	server.serveHTTP(response, request, "http", request.URL.Host)
	if upstreamCalls != 0 || response.Code != 202 || response.Body.String() != "mock body" {
		t.Fatalf("mocked response: calls=%d status=%d body=%q", upstreamCalls, response.Code, response.Body.String())
	}
	rows, err := db.List(10, "/mocked")
	if err != nil || len(rows) != 2 {
		t.Fatalf("mock response not captured: %d rows, %v", len(rows), err)
	}
}
