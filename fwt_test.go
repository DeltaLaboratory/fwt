package fwt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

var testHMACKey = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
var testEncryptionKey = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
var testEd25519PrivateKey ed25519.PrivateKey = []byte{0x8a, 0xea, 0xd7, 0xac, 0xf0, 0xae, 0x31, 0x59, 0x00, 0x26, 0x66, 0xec, 0x5a, 0x15, 0xdb, 0x6b, 0x97, 0x91, 0x30, 0xac, 0x2c, 0xa1, 0x32, 0x68, 0xa5, 0xda, 0xf7, 0xfb, 0xfe, 0xb4, 0x7f, 0x17, 0x22, 0x19, 0xc2, 0x27, 0x75, 0x08, 0x05, 0xc0, 0xee, 0xb3, 0x2c, 0x6d, 0xaa, 0x6e, 0x87, 0x8a, 0xba, 0x8f, 0xa0, 0x77, 0x97, 0x34, 0x43, 0xa6, 0x25, 0xc3, 0x78, 0x14, 0x52, 0x4b, 0x2b, 0xc6}
var testEd448PrivateKey ed448.PrivateKey = []byte{0xe8, 0x5f, 0xd4, 0x84, 0x38, 0x40, 0x79, 0xe9, 0x47, 0x70, 0xa9, 0xe9, 0xc8, 0x82, 0x23, 0xa4, 0x2b, 0xba, 0x41, 0x00, 0xae, 0x65, 0x16, 0x6e, 0x91, 0xf2, 0xa8, 0xdf, 0xb2, 0xa2, 0xb2, 0x9f, 0x95, 0x76, 0x56, 0x51, 0xb7, 0x48, 0x53, 0x1c, 0x95, 0x90, 0xc8, 0xaa, 0x3c, 0x86, 0x1a, 0xc7, 0x44, 0x6b, 0xda, 0x00, 0x7c, 0xd1, 0xf9, 0x47, 0x1a, 0x77, 0xe8, 0xfc, 0x42, 0xb0, 0x12, 0xd4, 0xbb, 0x42, 0xf3, 0x45, 0x06, 0xc7, 0x11, 0xee, 0xf6, 0xf4, 0x3f, 0x18, 0x2c, 0xa2, 0xd4, 0xa9, 0xaf, 0xe4, 0xeb, 0xf2, 0x7f, 0xb6, 0x52, 0x20, 0xdc, 0xfc, 0xf3, 0x39, 0x93, 0x03, 0xe3, 0xfa, 0xbb, 0xd2, 0xbc, 0xb3, 0xa3, 0xb4, 0x73, 0x72, 0x9f, 0xe8, 0x72, 0x26, 0xdd, 0x2f, 0x50, 0x55, 0x82, 0x80}

var testStruct = TestStruct{
	A: 42,
	B: "the answer to life, the universe and everything",
	C: time.Unix(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC).Unix(), 0),
	D: []byte("some bytes"),
}

func TestCreateEncryptedTokenXChaCha20Poly1305(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEncryptedTokenXChaCha20Poly1305(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalEncryptedTokenXChaCha20Poly1305(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey), SignatureTypeBlake2b256)

	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateEncryptedTokenAES256ECB(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEncryptedTokenAES256ECB(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalEncryptedTokenAES256ECB(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey), SignatureTypeBlake2b256)

	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateEncryptedTokenAES256CBC(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEncryptedTokenAES256CBC(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalEncryptedTokenAES256CBC(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey), SignatureTypeBlake2b256)

	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenAES256CTR(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenAES256CTR(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalTokenAES256CTR(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey), SignatureTypeBlake2b256)

	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenAES256GCM(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenAES256GCM(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalTokenAES256GCM(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey), SignatureTypeBlake2b256)

	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenHPKE(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	pk, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewHPKEEncryptor(pk, suite), SignatureTypeBlake2b256)
	_, err = signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenHPKE(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	pk, key, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewHPKEEncryptor(pk, suite), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewHPKEDecrypter(key, suite), SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalTokenHPKE(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	pk, key, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewHPKEEncryptor(pk, suite), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewHPKEDecrypter(key, suite), SignatureTypeBlake2b256)

	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenEd25519(t *testing.T) {
	signer := NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenEd25519(t *testing.T) {
	signer := NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalEd25519(t *testing.T) {
	signer := NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenEd448(t *testing.T) {
	signer := NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenEd448(t *testing.T) {
	signer := NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewEd448Verifier(testEd448PrivateKey.Public().(ed448.PublicKey)), nil, SignatureTypeEd448)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalEd448(t *testing.T) {
	signer := NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewEd448Verifier(testEd448PrivateKey.Public().(ed448.PublicKey)), nil, SignatureTypeEd448)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenHMACSha256(t *testing.T) {
	signer := NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenHMACSha256(t *testing.T) {
	signer := NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalHMACSha256(t *testing.T) {
	signer := NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenHMACSha512(t *testing.T) {
	signer := NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenHMACSha512(t *testing.T) {
	signer := NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalHMACSha512(t *testing.T) {
	signer := NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenBlake2b256(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenBlake2b256(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalBlake2b256(t *testing.T) {
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenBlake2b512(t *testing.T) {
	signer := NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenBlake2b512(t *testing.T) {
	signer := NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalBlake2b512(t *testing.T) {
	signer := NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func TestCreateTokenBlake3(t *testing.T) {
	signer := NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3)
	_, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenBlake3(t *testing.T) {
	signer := NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndUnmarshalBlake3(t *testing.T) {
	signer := NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3)
	token, err := signer.Sign(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	result := new(TestStruct)
	verifier := NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3)
	if err := verifier.Verify(token); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
		t.Fatal(err)
	}

	if result.A != testStruct.A {
		t.Fatalf("expected %d, got %d", testStruct.A, result.A)
	}
	if result.B != testStruct.B {
		t.Fatalf("expected %s, got %s", testStruct.B, result.B)
	}
}

func BenchmarkCreateEncryptedTokenXChaCha20Poly1305(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEncryptedTokenXChaCha20Poly1305(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEncryptedTokenXChaCha20Poly1305(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateEncryptedTokenAES256ECB(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEncryptedTokenAES256ECB(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEncryptedTokenAES256ECB(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateEncryptedTokenAES256CBC(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEncryptedTokenAES256CBC(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEncryptedTokenAES256CBC(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateEncryptedTokenAES256CTR(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEncryptedTokenAES256CTR(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEncryptedTokenAES256CTR(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateEncryptedTokenAES256GCM(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEncryptedTokenAES256GCM(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEncryptedTokenAES256GCM(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenHPKE(b *testing.B) {
	b.StopTimer()
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	pk, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewHPKEEncryptor(pk, suite), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err = signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenHPKE(b *testing.B) {
	b.StopTimer()
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	pk, key, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewHPKEEncryptor(pk, suite), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewHPKEDecrypter(key, suite), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalTokenHPKE(b *testing.B) {
	b.StopTimer()
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	pk, key, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	signer := NewSigner(NewBlake2b256Signer(testHMACKey), NewHPKEEncryptor(pk, suite), SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}

	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewHPKEDecrypter(key, suite), SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		result := new(TestStruct)
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenEd25519(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenEd25519(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEd25519(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenEd448(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenEd448(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewEd448Verifier(testEd448PrivateKey.Public().(ed448.PublicKey)), nil, SignatureTypeEd448)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalEd448(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewEd448Verifier(testEd448PrivateKey.Public().(ed448.PublicKey)), nil, SignatureTypeEd448)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenHMACSha256(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenHMACSha256(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalHMACSha256(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}

}

func BenchmarkCreateTokenHMACSha512(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenHMACSha512(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalHMACSha512(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenBlake2b256(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenBlake2b256(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalBlake2b256(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenBlake2b512(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenBlake2b512(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalBlake2b512(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenBlake3(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(testStruct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenBlake3(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	verifier := NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAndUnmarshalBlake3(b *testing.B) {
	b.StopTimer()
	signer := NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3)
	token, err := signer.Sign(testStruct)
	if err != nil {
		b.Fatal(err)
	}
	result := new(TestStruct)
	verifier := NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if err := verifier.VerifyAndUnmarshal(token, result); err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleSigner_Sign() {
	HMACKey := []byte("00000000000000000000000000000000")
	signer := NewSigner(NewBlake3Signer(HMACKey), nil, SignatureTypeBlake3)
	token, err := signer.Sign(testStruct)
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
	// Output: BkgAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAxpK+fBwBEpzb21lIGJ5dGVzLGyZyWWGXpPeYV0KJphXT0ZNMf3KTzKvOdFjltylKoI=
}

func ExampleVerifier_Verify() {
	HMACKey := []byte("00000000000000000000000000000000")
	verifier := NewVerifier(NewBlake3Verifier(HMACKey), nil, SignatureTypeBlake3)
	if err := verifier.Verify("BkgAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAxpK+fBwBEpzb21lIGJ5dGVzLGyZyWWGXpPeYV0KJphXT0ZNMf3KTzKvOdFjltylKoI="); err != nil {
		panic(err)
	}
	fmt.Println("token is valid")
	// Output: token is valid
}

func ExampleVerifier_VerifyAndUnmarshal() {
	HMACKey := []byte("00000000000000000000000000000000")
	verifier := NewVerifier(NewBlake3Verifier(HMACKey), nil, SignatureTypeBlake3)
	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal("BkgAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAxpK+fBwBEpzb21lIGJ5dGVzLGyZyWWGXpPeYV0KJphXT0ZNMf3KTzKvOdFjltylKoI=", result); err != nil {
		panic(err)
	}
	fmt.Printf("A: %d, B: %s, C: %s, D: %s", result.A, result.B, result.C.Format("2006-01-02"), result.D)
	// Output: A: 42, B: the answer to life, the universe and everything, C: 2009-11-11, D: some bytes
}

func FuzzVerify(f *testing.F) {
	// Setup
	testHMACKey := make([]byte, 32)
	if _, err := rand.Read(testHMACKey); err != nil {
		f.Fatal(err)
	}

	_, testEd25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	// Add some seed corpus
	f.Add(0, []byte{0, 0, 0, 0, 0, 0, 0, 0}, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8, 9, 10})

	// Fuzz test
	f.Fuzz(func(t *testing.T, sigType int, length []byte, data []byte, sig []byte) {
		// Test different verifiers
		verifiers := []struct {
			name     string
			verifier *Verifier
		}{
			{"Blake2b256", NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256)},
			{"Blake2b512", NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512)},
			{"Blake3", NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3)},
			{"HMACSha256", NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256)},
			{"HMACSha512", NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512)},
			{"Ed25519", NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519)},
		}

		txd := make([]byte, 0, 1+len(length)+len(data)+len(sig))
		txd = append(txd, byte(sigType))
		txd = append(txd, length...)
		txd = append(txd, data...)
		txd = append(txd, sig...)

		mxd := base64.StdEncoding.EncodeToString(txd)

		for _, v := range verifiers {
			// Test Verify
			err := v.verifier.Verify(mxd)
			if err != nil {
				// We expect some errors due to invalid input, so we don't fail the test
				t.Logf("%s Verify error: %v", v.name, err)
			}

			// Test VerifyAndUnmarshal
			result := new(TestStruct)
			err = v.verifier.VerifyAndUnmarshal(mxd, result)
			if err != nil {
				// We expect some errors due to invalid input, so we don't fail the test
				t.Logf("%s VerifyAndUnmarshal error: %v", v.name, err)
			}
		}
	})
}

func FuzzSign(f *testing.F) {
	// Setup
	testHMACKey := make([]byte, 32)
	if _, err := rand.Read(testHMACKey); err != nil {
		f.Fatal(err)
	}

	_, testEd25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	// Add some seed corpus
	f.Add(42, "test", []byte{1, 2, 3, 4})

	// Fuzz test
	f.Fuzz(func(t *testing.T, a int, b string, d []byte) {
		testStruct := TestStruct{
			A: a,
			B: b,
			C: testStruct.C, // Use the original time value
			D: d,
		}

		signersAndVerifiers := []struct {
			name     string
			signer   *Signer
			verifier *Verifier
		}{
			{
				"Blake2b256",
				NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256),
				NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256),
			},
			{
				"Blake2b512",
				NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512),
				NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512),
			},
			{
				"Blake3",
				NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3),
				NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3),
			},
			{
				"HMACSha256",
				NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256),
				NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256),
			},
			{
				"HMACSha512",
				NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512),
				NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512),
			},
			{
				"Ed25519",
				NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519),
				NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519),
			},
		}

		for _, sv := range signersAndVerifiers {
			// Sign the data
			token, err := sv.signer.Sign(testStruct)
			if err != nil {
				t.Logf("%s Sign error: %v", sv.name, err)
				continue
			}

			// Verify the token
			err = sv.verifier.Verify(token)
			if err != nil {
				t.Errorf("%s Verify error after successful Sign: %v: %s", sv.name, err, token)
				continue
			}

			// Unmarshal and verify the token
			result := new(TestStruct)
			err = sv.verifier.VerifyAndUnmarshal(token, result)
			if err != nil {
				t.Errorf("%s VerifyAndUnmarshal error after successful Sign: %v: %s", sv.name, err, token)
				continue
			}

			// Check if unmarshaled data matches original data
			if result.A != testStruct.A || result.B != testStruct.B || !bytes.Equal(result.D, testStruct.D) {
				t.Errorf("%s: Unmarshaled data does not match original. Original: %+v, Unmarshaled: %+v", sv.name, testStruct, result)
			}
		}
	})
}

type TestStruct struct {
	A int       `cbor:"1,keyasint"`
	B string    `cbor:"2,keyasint"`
	C time.Time `cbor:"3,keyasint"`
	D []byte    `cbor:"4,keyasint"`
}
