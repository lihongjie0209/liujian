package scripts

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleFormatsGzipJSONWithoutChangingWireBody(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "examples", "format-api.js"))
	if err != nil {
		t.Fatal(err)
	}
	runner := scriptRunner(t, string(source))
	producer := scriptRunner(t, `function onResponse(response) { response.body = ca.gzip.compress(ca.text.encode('{"a":1}')); return response; }`)
	input, _ := producer.Apply(context.Background(), "response", Exchange{Method: "GET", URL: "https://example.test/", Status: 200, Headers: http.Header{}}, 1024)
	input.Headers = http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}
	output, runs := runner.Apply(context.Background(), "response", input, 1024)
	if len(runs) != 1 || runs[0].Error != "" || !strings.Contains(runs[0].Display, "\n  \"a\": 1") || string(output.Body) != string(input.Body) {
		t.Fatalf("example output: %+v, runs: %+v", output, runs)
	}
}

func TestBuiltinsEncodingCompressionAndFormatting(t *testing.T) {
	runner := scriptRunner(t, `
function onResponse(response) {
  var original = ca.text.encode("海易办");
  var zipped = ca.gzip.compress(original);
  var encoded = ca.base64.encode(zipped);
  response.body = ca.gzip.decompress(ca.base64.decode(encoded));
  response.display = JSON.stringify({
    text: ca.text.decode(response.body),
    hex: ca.hex.encode(ca.hex.decode("00ff80")),
    url: ca.url.decode(ca.url.encode("海 易")),
    pretty: ca.json.pretty(ca.text.encode('{"a":1}')),
    urlBase64: ca.text.decode(ca.base64.urlDecode(ca.base64.urlEncode(original))),
    randomLength: ca.crypto.randomBytes(16).length
  });
  return response;
}`)
	response, runs := runner.Apply(context.Background(), "response", Exchange{Method: "GET", URL: "https://example.test/", Status: 200, Headers: http.Header{}, Body: []byte("original")}, 1024)
	if len(runs) != 1 || runs[0].Error != "" || string(response.Body) != "海易办" {
		t.Fatalf("builtins response: %+v, runs: %+v", response, runs)
	}
	for _, fragment := range []string{`"text":"海易办"`, `"hex":"00ff80"`, `"url":"海 易"`, `"urlBase64":"海易办"`, `"randomLength":16`, `\n  \"a\": 1`} {
		if !strings.Contains(runs[0].Display, fragment) {
			t.Errorf("missing %q in display %s", fragment, runs[0].Display)
		}
	}
}

func TestBuiltinsCryptographicKnownVectors(t *testing.T) {
	runner := scriptRunner(t, `
function onRequest(request) {
  var abc = ca.text.encode("abc");
  var key = ca.hex.decode("00000000000000000000000000000000");
  var nonce = ca.hex.decode("000000000000000000000000");
  var ciphertext = ca.crypto.aesGCMEncrypt(key, nonce, new Uint8Array(0));
  request.display = JSON.stringify({
    sha: ca.hex.encode(ca.crypto.sha256(abc)),
    hmac: ca.hex.encode(ca.crypto.hmacSHA256(ca.text.encode("key"), ca.text.encode("The quick brown fox jumps over the lazy dog"))),
    ciphertext: ca.hex.encode(ciphertext),
    plainLength: ca.crypto.aesGCMDecrypt(key, nonce, ciphertext).length
  });
  return request;
}`)
	_, runs := runner.Apply(context.Background(), "request", Exchange{Method: "POST", URL: "https://example.test/", Headers: http.Header{}}, 1024)
	if len(runs) != 1 || runs[0].Error != "" {
		t.Fatalf("crypto run: %+v", runs)
	}
	for _, fragment := range []string{
		`"sha":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`,
		`"hmac":"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"`,
		`"ciphertext":"58e2fccefa7e3061367f1d57a4e7455a"`,
		`"plainLength":0`,
	} {
		if !strings.Contains(runs[0].Display, fragment) {
			t.Errorf("missing %q in display %s", fragment, runs[0].Display)
		}
	}
}

func TestBuiltinsErrorsAreCatchableAndDecompressionIsLimited(t *testing.T) {
	runner := scriptRunner(t, `
function onResponse(response) {
  try { ca.base64.decode("not base64!"); } catch (error) { console.warn("invalid base64"); }
  response.body = ca.gzip.decompress(response.body);
  return response;
}`)
	producer := scriptRunner(t, `function onResponse(response) { response.body = ca.gzip.compress(ca.text.encode("x".repeat(4096))); return response; }`)
	compressed, runs := producer.Apply(context.Background(), "response", Exchange{Method: "GET", URL: "https://example.test/", Status: 200, Headers: http.Header{}}, 8192)
	if len(runs) != 1 || runs[0].Error != "" {
		t.Fatalf("gzip producer: %+v", runs)
	}
	original := Exchange{Method: "GET", URL: "https://example.test/", Status: 200, Headers: http.Header{}, Body: compressed.Body}
	response, runs := runner.Apply(context.Background(), "response", original, 1024)
	if len(runs) != 1 || !strings.Contains(runs[0].Error, "result exceeds") || !strings.Contains(runs[0].Console, "invalid base64") || string(response.Body) != string(original.Body) {
		t.Fatalf("oversized decompression: %+v, runs: %+v", response, runs)
	}
}
