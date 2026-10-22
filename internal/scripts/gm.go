package scripts

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/dop251/goja"
	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

const maxSM2Input = 64 << 10

func gmFunctions(vm *goja.Runtime, readBytes func(goja.Value) []byte, arrayBuffer func([]byte) goja.Value) map[string]func(goja.FunctionCall) goja.Value {
	throw := func(err error) { panic(vm.NewGoError(err)) }
	newSM4GCM := func(key []byte) cipher.AEAD {
		block, err := sm4.NewCipher(key)
		if err != nil {
			throw(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			throw(err)
		}
		return gcm
	}
	checkNonce := func(gcm cipher.AEAD, nonce []byte) {
		if len(nonce) != gcm.NonceSize() {
			panic(vm.NewTypeError("SM4-GCM nonce must be 12 bytes"))
		}
	}
	newSM4Block := func(key, iv []byte) cipher.Block {
		block, err := sm4.NewCipher(key)
		if err != nil {
			throw(err)
		}
		if len(iv) != block.BlockSize() {
			panic(vm.NewTypeError("SM4-CBC IV must be 16 bytes"))
		}
		return block
	}
	return map[string]func(goja.FunctionCall) goja.Value{
		"sm3": func(call goja.FunctionCall) goja.Value {
			sum := sm3.Sum(readBytes(call.Argument(0)))
			return arrayBuffer(sum[:])
		},
		"hmacSM3": func(call goja.FunctionCall) goja.Value {
			mac := hmac.New(sm3.New, readBytes(call.Argument(0)))
			_, _ = mac.Write(readBytes(call.Argument(1)))
			return arrayBuffer(mac.Sum(nil))
		},
		"sm4GCMEncrypt": func(call goja.FunctionCall) goja.Value {
			key, nonce, plain := readBytes(call.Argument(0)), readBytes(call.Argument(1)), readBytes(call.Argument(2))
			aad := optionalBytes(call.Argument(3), readBytes)
			gcm := newSM4GCM(key)
			checkNonce(gcm, nonce)
			return arrayBuffer(gcm.Seal(nil, nonce, plain, aad))
		},
		"sm4GCMDecrypt": func(call goja.FunctionCall) goja.Value {
			key, nonce, ciphertext := readBytes(call.Argument(0)), readBytes(call.Argument(1)), readBytes(call.Argument(2))
			aad := optionalBytes(call.Argument(3), readBytes)
			gcm := newSM4GCM(key)
			checkNonce(gcm, nonce)
			plain, err := gcm.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				throw(err)
			}
			return arrayBuffer(plain)
		},
		"sm4CBCEncrypt": func(call goja.FunctionCall) goja.Value {
			key, iv, plain := readBytes(call.Argument(0)), readBytes(call.Argument(1)), readBytes(call.Argument(2))
			block := newSM4Block(key, iv)
			padded := padding.NewPKCS7Padding(uint(block.BlockSize())).Pad(plain)
			ciphertext := make([]byte, len(padded))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
			return arrayBuffer(ciphertext)
		},
		"sm4CBCDecrypt": func(call goja.FunctionCall) goja.Value {
			key, iv, ciphertext := readBytes(call.Argument(0)), readBytes(call.Argument(1)), readBytes(call.Argument(2))
			block := newSM4Block(key, iv)
			if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
				panic(vm.NewTypeError("SM4-CBC ciphertext must contain complete blocks"))
			}
			padded := make([]byte, len(ciphertext))
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
			plain, err := padding.NewPKCS7Padding(uint(block.BlockSize())).Unpad(padded)
			if err != nil {
				throw(err)
			}
			return arrayBuffer(plain)
		},
		"sm2Encrypt": func(call goja.FunctionCall) goja.Value {
			key, plain := readBytes(call.Argument(0)), readBytes(call.Argument(1))
			if len(plain) > maxSM2Input {
				panic(vm.NewTypeError("SM2 plaintext exceeds 64 KiB"))
			}
			publicKey, err := sm2.NewPublicKey(key)
			if err != nil {
				throw(fmt.Errorf("SM2 public key: %w", err))
			}
			opts, err := sm2EncryptOptions(call.Argument(2))
			if err != nil {
				throw(err)
			}
			ciphertext, err := sm2.Encrypt(rand.Reader, publicKey, plain, opts)
			if err != nil {
				throw(err)
			}
			return arrayBuffer(ciphertext)
		},
		"sm2Decrypt": func(call goja.FunctionCall) goja.Value {
			key, ciphertext := readBytes(call.Argument(0)), readBytes(call.Argument(1))
			if len(ciphertext) > maxSM2Input+256 {
				panic(vm.NewTypeError("SM2 ciphertext exceeds 64 KiB"))
			}
			privateKey, err := sm2.NewPrivateKey(key)
			if err != nil {
				throw(fmt.Errorf("SM2 private key: %w", err))
			}
			opts, err := sm2DecryptOptions(call.Argument(2))
			if err != nil {
				throw(err)
			}
			plain, err := privateKey.Decrypt(nil, ciphertext, opts)
			if err != nil {
				throw(err)
			}
			return arrayBuffer(plain)
		},
	}
}

func sm2EncryptOptions(value goja.Value) (*sm2.EncrypterOpts, error) {
	switch sm2Format(value) {
	case "c1c3c2":
		return nil, nil
	case "c1c2c3":
		return sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3), nil
	case "asn1":
		return sm2.ASN1EncrypterOpts, nil
	default:
		return nil, fmt.Errorf("SM2 format must be c1c3c2, c1c2c3, or asn1")
	}
}

func sm2DecryptOptions(value goja.Value) (*sm2.DecrypterOpts, error) {
	switch sm2Format(value) {
	case "c1c3c2":
		return nil, nil
	case "c1c2c3":
		return sm2.NewPlainDecrypterOpts(sm2.C1C2C3), nil
	case "asn1":
		return sm2.ASN1DecrypterOpts, nil
	default:
		return nil, fmt.Errorf("SM2 format must be c1c3c2, c1c2c3, or asn1")
	}
}

func sm2Format(value goja.Value) string {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) || value.String() == "" {
		return "c1c3c2"
	}
	return strings.ToLower(value.String())
}
