package replay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/store"
)

func TestReplayRecordsResponseAndExportsCurl(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(body) != "hello" || r.Header.Get("X-Test") != "quote' here" {
			t.Errorf("replayed request: %s %q %v", r.Method, body, r.Header)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer upstream.Close()
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	saved := &store.Session{Time: time.Now(), Method: "POST", URL: upstream.URL + "/submit", RequestHeaders: http.Header{"X-Test": {"quote' here"}}, RequestBody: []byte("hello")}
	id, err := db.Save(saved)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Send(context.Background(), db, id, time.Second*5)
	if err != nil || result.Status != 201 || string(result.ResponseBody) != "created" || result.ClientAddr != "replay:1" {
		t.Fatalf("replay result: %+v, %v", result, err)
	}
	line, err := Curl(saved)
	if err != nil || !strings.Contains(line, "quote'\\'' here") || !strings.Contains(line, "--data-binary @-") {
		t.Fatalf("curl command: %q, %v", line, err)
	}
}

func TestReplayRejectsTruncatedRequest(t *testing.T) {
	_, err := Request(context.Background(), &store.Session{Method: "POST", URL: "http://example.test", RequestTruncated: true})
	if err == nil {
		t.Fatal("truncated request accepted")
	}
}
