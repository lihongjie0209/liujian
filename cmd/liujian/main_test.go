package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/headless"
	"github.com/lihongjie0209/liujian/internal/store"
)

func TestCAExportProfileSelection(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, profile, subject string
	}{
		{name: "default", subject: "EM DV TLS CA - G3C"},
		{name: "explicit", profile: "EM-OV-TLS-CA-G3B", subject: "EM OV TLS CA - G3B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".pem")
			args := []string{"--data-dir", dir}
			if tc.profile != "" {
				args = append(args, "--ca-profile", tc.profile)
			}
			args = append(args, "ca", "export", path)
			cmd := rootCommand()
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			if block == nil {
				t.Fatal("no exported certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if cert.Subject.CommonName != tc.subject {
				t.Fatalf("CA subject = %q, want %q", cert.Subject.CommonName, tc.subject)
			}
		})
	}
	cmd := rootCommand()
	cmd.SetArgs([]string{"--ca-profile", "unknown", "ca", "export", filepath.Join(dir, "bad.pem")})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown CA profile") {
		t.Fatalf("invalid profile error = %v", err)
	}
}

func TestStreamNewEmitsSessionsAndLiveMessagesOnce(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: "http://old.test"})
	if err != nil {
		t.Fatal(err)
	}
	lastSession, lastMessage, err := db.LatestIDs()
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: "http://new.test", Status: 101})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(id, store.Message{Time: time.Now(), Protocol: "sse", Body: []byte("event")}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	out := &headless.Output{Writer: &buf, Format: "jsonl", BodyDir: dir, InlineBytes: 10}
	if err := streamNew(db, out, &lastSession, &lastMessage); err != nil {
		t.Fatal(err)
	}
	first := buf.String()
	if err := streamNew(db, out, &lastSession, &lastMessage); err != nil {
		t.Fatal(err)
	}
	if first != buf.String() {
		t.Fatal("events emitted twice")
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 JSONL events, got %d: %s", len(lines), buf.String())
	}
	var events []headless.Event
	for _, line := range lines {
		var event headless.Event
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if events[0].URL != "http://new.test" || events[1].Type != "sse_message" || events[1].SessionID != id {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestStreamNewAppliesFilterToSessionsAndMessages(t *testing.T) {
	db, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"skip", "keep"} {
		id, err := db.Save(&store.Session{Time: time.Now(), Method: "GET", URL: "https://example.test/" + name})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AddMessage(id, store.Message{Time: time.Now(), Protocol: "websocket", Body: []byte(name)}); err != nil {
			t.Fatal(err)
		}
	}
	filter, err := store.ParseFilter("url:/keep")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	out := &headless.Output{Writer: &output, Format: "jsonl", InlineBytes: 100, Filter: filter}
	var lastSession, lastMessage int64
	if err := streamNew(db, out, &lastSession, &lastMessage); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "skip") || !strings.Contains(output.String(), "/keep") || !strings.Contains(output.String(), `"body"`) {
		t.Fatalf("filtered stream: %s", output.String())
	}
}

func TestRunDefaultsToAllIPv4Interfaces(t *testing.T) {
	cmd := rootCommand()
	run, _, err := cmd.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	flag := run.Flags().Lookup("listen-ip")
	if flag == nil || flag.DefValue != "0.0.0.0" {
		t.Fatalf("default listen-ip = %v, want 0.0.0.0", flag)
	}
}
