package fwt

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

var testHMACKey []byte
var testEncryptionKey []byte
var testEd25519PrivateKey ed25519.PrivateKey
var testEd448PrivateKey ed448.PrivateKey

var testStruct = TestStruct{
	A: 42,
	B: "the answer to life, the universe and everything",
	C: time.Unix(0, 0),
	D: []byte("some bytes"),
}

func TestMain(m *testing.M) {
	var err error
	testHMACKey = make([]byte, 32)
	if _, err := rand.Read(testHMACKey); err != nil {
		panic(err)
	}
	testEncryptionKey = make([]byte, 32)
	if _, err := rand.Read(testEncryptionKey); err != nil {
		panic(err)
	}
	_, testEd25519PrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	_, testEd448PrivateKey, err = ed448.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	m.Run()
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
	// Output: BkQAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAwAESnNvbWUgYnl0ZXNfUfdgdxFn2YAdHaO3VFbnyNTQOKBjc1/dlonKx8vE/Q==
}

func ExampleVerifier_Verify() {
	HMACKey := []byte("00000000000000000000000000000000")
	verifier := NewVerifier(NewBlake3Verifier(HMACKey), nil, SignatureTypeBlake3)
	if err := verifier.Verify("BkQAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAwAESnNvbWUgYnl0ZXNfUfdgdxFn2YAdHaO3VFbnyNTQOKBjc1/dlonKx8vE/Q=="); err != nil {
		panic(err)
	}
	fmt.Println("token is valid")
	// Output: token is valid
}

func ExampleVerifier_VerifyAndUnmarshal() {
	HMACKey := []byte("00000000000000000000000000000000")
	verifier := NewVerifier(NewBlake3Verifier(HMACKey), nil, SignatureTypeBlake3)
	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal("BkQAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAwAESnNvbWUgYnl0ZXNfUfdgdxFn2YAdHaO3VFbnyNTQOKBjc1/dlonKx8vE/Q==", result); err != nil {
		panic(err)
	}
	fmt.Printf("A: %d, B: %s, C: %s, D: %s", result.A, result.B, result.C.Format("2006-01-02"), result.D)
	// Output: A: 42, B: the answer to life, the universe and everything, C: 1970-01-01, D: some bytes
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
	f.Add([]byte("BkQAAAAAAAAApAEYKgJ4L3RoZSBhbnN3ZXIgdG8gbGlmZSwgdGhlIHVuaXZlcnNlIGFuZCBldmVyeXRoaW5nAwAESnNvbWUgYnl0ZXNfUfdgdxFn2YAdHaO3VFbnyNTQOKBjc1/dlonKx8vE/Q=="))

	// Fuzz test
	f.Fuzz(func(t *testing.T, data []byte) {
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

		for _, v := range verifiers {
			// Test Verify
			err := v.verifier.Verify(string(data))
			if err != nil {
				// We expect some errors due to invalid input, so we don't fail the test
				t.Logf("%s Verify error: %v", v.name, err)
			}

			// Test VerifyAndUnmarshal
			result := new(TestStruct)
			err = v.verifier.VerifyAndUnmarshal(string(data), result)
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
