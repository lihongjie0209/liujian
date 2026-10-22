package scripts

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestSM3AndSM4KnownVectors(t *testing.T) {
	runner := scriptRunner(t, `
function onRequest(request) {
  var key = ca.hex.decode("0123456789abcdeffedcba9876543210");
  var iv = new Uint8Array(16);
  var plain = ca.hex.decode("0123456789abcdeffedcba9876543210");
  var cbc = ca.gm.sm4CBCEncrypt(key, iv, plain);
  var nonce = new Uint8Array(12);
  var gcm = ca.gm.sm4GCMEncrypt(key, nonce, plain, ca.text.encode("aad"));
  request.display = JSON.stringify({
    sm3: ca.hex.encode(ca.gm.sm3(ca.text.encode("abc"))),
    sm4FirstBlock: ca.hex.encode(cbc.slice(0, 16)),
    cbcPlain: ca.hex.encode(ca.gm.sm4CBCDecrypt(key, iv, cbc)),
    gcmPlain: ca.hex.encode(ca.gm.sm4GCMDecrypt(key, nonce, gcm, ca.text.encode("aad"))),
    hmacLength: ca.gm.hmacSM3(key, plain).length
  });
  return request;
}`)
	_, runs := runner.Apply(context.Background(), "request", Exchange{Method: "POST", URL: "https://example.test/", Headers: http.Header{}}, 1024)
	if len(runs) != 1 || runs[0].Error != "" {
		t.Fatalf("SM3/SM4 run: %+v", runs)
	}
	for _, fragment := range []string{
		`"sm3":"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"`,
		`"sm4FirstBlock":"681edf34d206965e86b3e94f536e4246"`,
		`"cbcPlain":"0123456789abcdeffedcba9876543210"`,
		`"gcmPlain":"0123456789abcdeffedcba9876543210"`,
		`"hmacLength":32`,
	} {
		if !strings.Contains(runs[0].Display, fragment) {
			t.Errorf("missing %q in %s", fragment, runs[0].Display)
		}
	}
}

func TestSM2FormatsThroughScript(t *testing.T) {
	privateBytes := make([]byte, 32)
	privateBytes[31] = 1
	privateKey, err := sm2.NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	for _, format := range []string{"c1c3c2", "c1c2c3", "asn1"} {
		t.Run(format, func(t *testing.T) {
			source := fmt.Sprintf(`function onRequest(request) {
  var publicKey = ca.hex.decode(%q);
  var privateKey = ca.hex.decode(%q);
  var ciphertext = ca.gm.sm2Encrypt(publicKey, ca.text.encode("海易办 test"), %q);
  request.display = ca.text.decode(ca.gm.sm2Decrypt(privateKey, ciphertext, %q));
  return request;
}`, hex.EncodeToString(publicBytes), hex.EncodeToString(privateBytes), format, format)
			runner := scriptRunner(t, source)
			_, runs := runner.Apply(context.Background(), "request", Exchange{Method: "GET", URL: "https://example.test/", Headers: http.Header{}}, 1024)
			if len(runs) != 1 || runs[0].Error != "" || runs[0].Display != "海易办 test" {
				t.Fatalf("SM2 %s: %+v", format, runs)
			}
		})
	}
}

func TestGMInvalidCiphertextIsCatchable(t *testing.T) {
	runner := scriptRunner(t, `function onResponse(response) {
  try { ca.gm.sm4CBCDecrypt(new Uint8Array(16), new Uint8Array(16), new Uint8Array([1])); }
  catch (error) { response.display = "caught SM4 error"; }
  return response;
}`)
	response, runs := runner.Apply(context.Background(), "response", Exchange{Method: "GET", URL: "https://example.test/", Status: 200, Headers: http.Header{}, Body: []byte("original")}, 1024)
	if len(runs) != 1 || runs[0].Error != "" || runs[0].Display != "caught SM4 error" || string(response.Body) != "original" {
		t.Fatalf("invalid ciphertext handling: %+v, runs: %+v", response, runs)
	}
}
