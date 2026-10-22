package headless

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/store"
)

func TestJSONLinesAndBodyFiles(t *testing.T) {
	dir := t.TempDir()
	var text bytes.Buffer
	o := &Output{Writer: &text, Format: "jsonl", BodyDir: filepath.Join(dir, "bodies"), InlineBytes: 5}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	session := &store.Session{ID: 7, Time: time.Now(), Method: "POST", URL: "https://example.test/api", Status: 200, RequestBody: []byte(`{"a":1}`), ResponseBody: []byte("ok"), RequestTruncated: true}
	if err := o.WriteSession(session); err != nil {
		t.Fatal(err)
	}
	msg := store.StreamMessage{ID: 9, SessionID: 7, Message: store.Message{Time: time.Now(), Protocol: "websocket", FromClient: true, Body: []byte{0xff, 0x00}}}
	if err := o.WriteMessage(msg); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(text.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %s", len(lines), text.String())
	}
	var first, second Event
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatal(err)
	}
	if first.Type != "session" || first.RequestBody.Path == "" || first.RequestBody.Text != "" || !first.RequestBody.Truncated || first.ResponseBody.Text != "ok" {
		t.Fatalf("unexpected session line: %+v", first)
	}
	got, err := os.ReadFile(first.RequestBody.Path)
	if err != nil || string(got) != string(session.RequestBody) {
		t.Fatalf("body file = %q, err=%v", got, err)
	}
	info, err := os.Stat(first.RequestBody.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("body permissions = %v, err=%v", info, err)
	}
	if second.Type != "websocket_message" || second.SessionID != 7 || second.Direction != "client_to_server" || second.Body.Encoding != "base64" || second.Body.Base64 != "/wA=" {
		t.Fatalf("unexpected message line: %+v", second)
	}
}

func TestInvalidOutputConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output Output
	}{
		{"missing writer", Output{Format: "jsonl"}},
		{"bad format", Output{Writer: &bytes.Buffer{}, Format: "xml"}},
		{"negative threshold", Output{Writer: &bytes.Buffer{}, Format: "console", InlineBytes: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.output.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
