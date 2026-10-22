package scripts

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scriptRunner(t *testing.T, sources ...string) *Runner {
	t.Helper()
	dir := t.TempDir()
	var cfg Config
	for i, source := range sources {
		name := string(rune('a' + i))
		file := name + ".js"
		if err := os.WriteFile(filepath.Join(dir, file), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Scripts = append(cfg.Scripts, Definition{Name: name, File: file, TimeoutMS: 100})
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "scripts.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	runner, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestScriptsModifyBinaryBodiesAndRunInOrder(t *testing.T) {
	runner := scriptRunner(t,
		`function onRequest(request) { console.log("first"); request.body = new Uint8Array([0, 255, 1]); request.headers["X-Step"] = ["first"]; request.display = "decoded first"; return request; }
         function onResponse(response) { response.body = new Uint8Array([1, 0, 254]); response.headers["Content-Type"] = ["application/octet-stream"]; return response; }`,
		`function onRequest(request) { if (request.body[1] !== 255) throw Error("order"); request.body[2] = 2; request.display = "second"; return request; }
         function onResponse(response) { response.status = 201; return response; }`,
	)
	request, runs := runner.Apply(context.Background(), "request", Exchange{Method: "POST", URL: "https://example.test/api", Headers: http.Header{}, Body: []byte("input")}, 1024)
	if len(runs) != 2 || runs[0].Error != "" || runs[1].Error != "" || runs[0].Display != "decoded first" || !strings.Contains(runs[0].Console, "first") {
		t.Fatalf("request runs: %+v", runs)
	}
	if string(request.Body) != string([]byte{0, 255, 2}) || request.Headers.Get("X-Step") != "first" {
		t.Fatalf("modified request: %+v", request)
	}
	response, runs := runner.Apply(context.Background(), "response", Exchange{Method: "POST", URL: request.URL, Status: 200, Headers: http.Header{}, Body: []byte("upstream")}, 1024)
	if len(runs) != 2 || runs[0].Error != "" || runs[1].Error != "" || response.Status != 201 || string(response.Body) != string([]byte{1, 0, 254}) {
		t.Fatalf("modified response: %+v, runs: %+v", response, runs)
	}
}

func TestScriptFailureDoesNotBlockLaterScripts(t *testing.T) {
	runner := scriptRunner(t,
		`function onRequest(request) { throw Error("broken"); }`,
		`function onRequest(request) { request.body = new Uint8Array([42]); return request; }`,
	)
	request, runs := runner.Apply(context.Background(), "request", Exchange{Method: "GET", URL: "https://example.test/", Headers: http.Header{}, Body: []byte{1}}, 1024)
	if len(runs) != 2 || !strings.Contains(runs[0].Error, "broken") || runs[1].Error != "" || string(request.Body) != "*" {
		t.Fatalf("runs: %+v, request: %+v", runs, request)
	}
}

func TestTextHelpersAndMissingPhase(t *testing.T) {
	runner := scriptRunner(t, `function onResponse(response) { response.display = utf8Decode(response.body); response.body = utf8Encode("你好"); return response; }`)
	request, runs := runner.Apply(context.Background(), "request", Exchange{Method: "GET", URL: "https://example.test/", Headers: http.Header{}}, 1024)
	if len(runs) != 0 || request.Method != "GET" {
		t.Fatalf("request phase: %+v %+v", request, runs)
	}
	response, runs := runner.Apply(context.Background(), "response", Exchange{Method: "GET", URL: request.URL, Status: 200, Headers: http.Header{}, Body: []byte("original")}, 1024)
	if len(runs) != 1 || runs[0].Error != "" || runs[0].Display != "original" || string(response.Body) != "你好" {
		t.Fatalf("response phase: %+v %+v", response, runs)
	}
}

func TestScriptTimeoutKeepsOriginalBody(t *testing.T) {
	runner := scriptRunner(t, `function onRequest(request) { while (true) {} }`)
	runner.scripts[0].definition.TimeoutMS = 10
	original := Exchange{Method: "POST", URL: "https://example.test/", Headers: http.Header{}, Body: []byte("keep")}
	request, runs := runner.Apply(context.Background(), "request", original, 1024)
	if len(runs) != 1 || !strings.Contains(runs[0].Error, "timeout") || string(request.Body) != "keep" {
		t.Fatalf("timeout result: %+v %+v", request, runs)
	}
}

func TestScriptCanReturnNewObject(t *testing.T) {
	runner := scriptRunner(t, `function onResponse(response) { return { status: 202, headers: { "content-type": ["application/custom"] }, body: new Uint8Array([3, 2, 1]), display: "decoded" }; }`)
	response, runs := runner.Apply(context.Background(), "response", Exchange{Method: "GET", URL: "https://example.test/", Status: 200, Headers: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("old")}, 1024)
	if len(runs) != 1 || runs[0].Error != "" || response.Status != 202 || response.Headers.Get("Content-Type") != "application/custom" || string(response.Body) != string([]byte{3, 2, 1}) {
		t.Fatalf("new response object: %+v %+v", response, runs)
	}
}
