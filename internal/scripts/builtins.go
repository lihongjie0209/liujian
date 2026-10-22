package scripts

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/dop251/goja"
)

const defaultHelperLimit = 10 << 20
const consoleLimit = 2 << 20

func installBuiltins(vm *goja.Runtime, bodyLimit int64, logs *strings.Builder) error {
	limit := bodyLimit
	if limit <= 0 {
		limit = defaultHelperLimit
	}
	readBytes := func(value goja.Value) []byte {
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			panic(vm.NewTypeError("expected Uint8Array"))
		}
		var data []byte
		if err := vm.ExportTo(value, &data); err != nil {
			panic(vm.NewTypeError("expected Uint8Array: %s", err))
		}
		if int64(len(data)) > limit {
			panic(vm.NewTypeError("input exceeds script body limit"))
		}
		return data
	}
	arrayBuffer := func(data []byte) goja.Value {
		if int64(len(data)) > limit {
			panic(vm.NewTypeError("result exceeds script body limit"))
		}
		return vm.ToValue(vm.NewArrayBuffer(data))
	}
	throw := func(err error) {
		panic(vm.NewGoError(err))
	}
	console := vm.NewObject()
	const truncatedLog = "\n[console truncated]\n"
	logTruncated := false
	appendLog := func(value string) {
		if logTruncated {
			return
		}
		remaining := consoleLimit - len(truncatedLog) - logs.Len()
		if len(value) > remaining {
			if remaining > 0 {
				logs.WriteString(value[:remaining])
			}
			logs.WriteString(truncatedLog)
			logTruncated = true
			return
		}
		logs.WriteString(value)
	}
	for _, level := range []string{"log", "warn", "error"} {
		level := level
		if err := console.Set(level, func(args ...any) {
			if logs.Len() >= consoleLimit {
				return
			}
			if level != "log" {
				appendLog(level + ": ")
			}
			for i, arg := range args {
				if i > 0 {
					appendLog(" ")
				}
				appendLog(fmt.Sprint(arg))
				if logs.Len() >= consoleLimit {
					break
				}
			}
			appendLog("\n")
		}); err != nil {
			return err
		}
	}
	if err := vm.Set("console", console); err != nil {
		return err
	}
	native := vm.NewObject()
	functions := map[string]func(goja.FunctionCall) goja.Value{
		"utf8Encode": func(call goja.FunctionCall) goja.Value {
			return arrayBuffer([]byte(call.Argument(0).String()))
		},
		"utf8Decode": func(call goja.FunctionCall) goja.Value {
			return vm.ToValue(string(readBytes(call.Argument(0))))
		},
		"base64Encode": func(call goja.FunctionCall) goja.Value {
			return vm.ToValue(base64.StdEncoding.EncodeToString(readBytes(call.Argument(0))))
		},
		"base64Decode": func(call goja.FunctionCall) goja.Value {
			data, err := base64.StdEncoding.DecodeString(call.Argument(0).String())
			if err != nil {
				throw(err)
			}
			return arrayBuffer(data)
		},
		"base64URLEncode": func(call goja.FunctionCall) goja.Value {
			return vm.ToValue(base64.RawURLEncoding.EncodeToString(readBytes(call.Argument(0))))
		},
		"base64URLDecode": func(call goja.FunctionCall) goja.Value {
			data, err := base64.RawURLEncoding.DecodeString(call.Argument(0).String())
			if err != nil {
				data, err = base64.URLEncoding.DecodeString(call.Argument(0).String())
			}
			if err != nil {
				throw(err)
			}
			return arrayBuffer(data)
		},
		"hexEncode": func(call goja.FunctionCall) goja.Value {
			return vm.ToValue(hex.EncodeToString(readBytes(call.Argument(0))))
		},
		"hexDecode": func(call goja.FunctionCall) goja.Value {
			data, err := hex.DecodeString(call.Argument(0).String())
			if err != nil {
				throw(err)
			}
			return arrayBuffer(data)
		},
		"gzipCompress": func(call goja.FunctionCall) goja.Value {
			var output bytes.Buffer
			writer := gzip.NewWriter(&output)
			if _, err := writer.Write(readBytes(call.Argument(0))); err != nil {
				throw(err)
			}
			if err := writer.Close(); err != nil {
				throw(err)
			}
			return arrayBuffer(output.Bytes())
		},
		"gzipDecompress": func(call goja.FunctionCall) goja.Value {
			reader, err := gzip.NewReader(bytes.NewReader(readBytes(call.Argument(0))))
			if err != nil {
				throw(err)
			}
			defer reader.Close()
			data, err := io.ReadAll(io.LimitReader(reader, limit+1))
			if err != nil {
				throw(err)
			}
			return arrayBuffer(data)
		},
		"sha256": func(call goja.FunctionCall) goja.Value {
			sum := sha256.Sum256(readBytes(call.Argument(0)))
			return arrayBuffer(sum[:])
		},
		"hmacSHA256": func(call goja.FunctionCall) goja.Value {
			mac := hmac.New(sha256.New, readBytes(call.Argument(0)))
			_, _ = mac.Write(readBytes(call.Argument(1)))
			return arrayBuffer(mac.Sum(nil))
		},
		"randomBytes": func(call goja.FunctionCall) goja.Value {
			size := call.Argument(0).ToInteger()
			if size < 0 || size > limit || size > 1<<20 {
				panic(vm.NewTypeError("random byte count must be 0..min(body limit, 1 MiB)"))
			}
			data := make([]byte, size)
			if _, err := rand.Read(data); err != nil {
				throw(err)
			}
			return arrayBuffer(data)
		},
		"aesGCMEncrypt": func(call goja.FunctionCall) goja.Value {
			key, nonce, plain := readBytes(call.Argument(0)), readBytes(call.Argument(1)), readBytes(call.Argument(2))
			aad := optionalBytes(call.Argument(3), readBytes)
			gcm, err := newGCM(key)
			if err != nil {
				throw(err)
			}
			if len(nonce) != gcm.NonceSize() {
				panic(vm.NewTypeError("AES-GCM nonce must be 12 bytes"))
			}
			return arrayBuffer(gcm.Seal(nil, nonce, plain, aad))
		},
		"aesGCMDecrypt": func(call goja.FunctionCall) goja.Value {
			key, nonce, ciphertext := readBytes(call.Argument(0)), readBytes(call.Argument(1)), readBytes(call.Argument(2))
			aad := optionalBytes(call.Argument(3), readBytes)
			gcm, err := newGCM(key)
			if err != nil {
				throw(err)
			}
			if len(nonce) != gcm.NonceSize() {
				panic(vm.NewTypeError("AES-GCM nonce must be 12 bytes"))
			}
			plain, err := gcm.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				throw(err)
			}
			return arrayBuffer(plain)
		},
		"urlEncode": func(call goja.FunctionCall) goja.Value {
			return vm.ToValue(url.QueryEscape(call.Argument(0).String()))
		},
		"urlDecode": func(call goja.FunctionCall) goja.Value {
			value, err := url.QueryUnescape(call.Argument(0).String())
			if err != nil {
				throw(err)
			}
			return vm.ToValue(value)
		},
		"jsonPretty": func(call goja.FunctionCall) goja.Value {
			var output bytes.Buffer
			if err := json.Indent(&output, readBytes(call.Argument(0)), "", "  "); err != nil {
				throw(err)
			}
			if int64(output.Len()) > limit {
				panic(vm.NewTypeError("formatted JSON exceeds script body limit"))
			}
			return vm.ToValue(output.String())
		},
	}
	for name, function := range functions {
		if err := native.Set(name, function); err != nil {
			return err
		}
	}
	for name, function := range gmFunctions(vm, readBytes, arrayBuffer) {
		if err := native.Set(name, function); err != nil {
			return err
		}
	}
	if err := vm.Set("__caNative", native); err != nil {
		return err
	}
	_, err := vm.RunString(helperBootstrap)
	return err
}

func optionalBytes(value goja.Value, read func(goja.Value) []byte) []byte {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return nil
	}
	return read(value)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM: %w", err)
	}
	return gcm, nil
}

const helperBootstrap = `
(function () {
  var n = __caNative;
  function bytes(value) { return new Uint8Array(value); }
  var helpers = {
    text: { encode: function (value) { return bytes(n.utf8Encode(value)); }, decode: n.utf8Decode },
    base64: {
      encode: n.base64Encode, decode: function (value) { return bytes(n.base64Decode(value)); },
      urlEncode: n.base64URLEncode, urlDecode: function (value) { return bytes(n.base64URLDecode(value)); }
    },
    hex: { encode: n.hexEncode, decode: function (value) { return bytes(n.hexDecode(value)); } },
    gzip: {
      compress: function (value) { return bytes(n.gzipCompress(value)); },
      decompress: function (value) { return bytes(n.gzipDecompress(value)); }
    },
    crypto: {
      sha256: function (value) { return bytes(n.sha256(value)); },
      hmacSHA256: function (key, value) { return bytes(n.hmacSHA256(key, value)); },
      randomBytes: function (count) { return bytes(n.randomBytes(count)); },
      aesGCMEncrypt: function (key, nonce, value, aad) { return bytes(n.aesGCMEncrypt(key, nonce, value, aad)); },
      aesGCMDecrypt: function (key, nonce, value, aad) { return bytes(n.aesGCMDecrypt(key, nonce, value, aad)); }
    },
    gm: {
      sm3: function (value) { return bytes(n.sm3(value)); },
      hmacSM3: function (key, value) { return bytes(n.hmacSM3(key, value)); },
      sm4GCMEncrypt: function (key, nonce, value, aad) { return bytes(n.sm4GCMEncrypt(key, nonce, value, aad)); },
      sm4GCMDecrypt: function (key, nonce, value, aad) { return bytes(n.sm4GCMDecrypt(key, nonce, value, aad)); },
      sm4CBCEncrypt: function (key, iv, value) { return bytes(n.sm4CBCEncrypt(key, iv, value)); },
      sm4CBCDecrypt: function (key, iv, value) { return bytes(n.sm4CBCDecrypt(key, iv, value)); },
      sm2Encrypt: function (publicKey, value, format) { return bytes(n.sm2Encrypt(publicKey, value, format)); },
      sm2Decrypt: function (privateKey, value, format) { return bytes(n.sm2Decrypt(privateKey, value, format)); }
    },
    url: { encode: n.urlEncode, decode: n.urlDecode },
    json: { pretty: n.jsonPretty }
  };
  Object.freeze(helpers.text); Object.freeze(helpers.base64); Object.freeze(helpers.hex);
  Object.freeze(helpers.gzip); Object.freeze(helpers.crypto); Object.freeze(helpers.url);
  Object.freeze(helpers.json); Object.freeze(helpers.gm);
  globalThis.ca = Object.freeze(helpers);
  globalThis.utf8Encode = helpers.text.encode;
  globalThis.utf8Decode = helpers.text.decode;
})();`
