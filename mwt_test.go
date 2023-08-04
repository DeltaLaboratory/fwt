package mwt

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

var testEd25519PrivateKey ed25519.PrivateKey
var testEd448PrivateKey ed448.PrivateKey

var testStruct = TestStruct{
	A: 42,
	B: "the answer to life, the universe and everything",
}

func TestMain(m *testing.M) {
	var err error
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

func TestCreateTokenEd25519(t *testing.T) {
	token, err := CreateToken(testStruct, testEd25519PrivateKey, SignatureTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token: %s", token)
}

func TestVerifyTokenEd25519(t *testing.T) {
	token, err := CreateToken(testStruct, testEd25519PrivateKey, SignatureTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token: %s", token)

	result, err := VerifyToken[TestStruct](token, testEd25519PrivateKey.Public())

	if err != nil {
		t.Fatal(err)
	}
	if result.A != testStruct.A || result.B != testStruct.B {
		t.Fatalf("result: %+v, expected: %+v", result, testStruct)
	}
	t.Logf("result: %+v", result)
}

func TestCreateTokenEd448(t *testing.T) {
	token, err := CreateToken(testStruct, testEd448PrivateKey, SignatureTypeEd448)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token: %s", token)
}

func TestVerifyTokenEd448(t *testing.T) {
	token, err := CreateToken(testStruct, testEd448PrivateKey, SignatureTypeEd448)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token: %s", token)

	result, err := VerifyToken[TestStruct](token, testEd448PrivateKey.Public())

	if err != nil {
		t.Fatal(err)
	}
	if result.A != testStruct.A || result.B != testStruct.B {
		t.Fatalf("result: %+v, expected: %+v", result, testStruct)
	}
	t.Logf("result: %+v", result)
}

func BenchmarkCreateTokenEd25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := CreateToken(testStruct, testEd25519PrivateKey, SignatureTypeEd25519)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenEd25519(b *testing.B) {
	token, err := CreateToken(testStruct, testEd25519PrivateKey, SignatureTypeEd25519)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, err := VerifyToken[TestStruct](token, testEd25519PrivateKey.Public())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateTokenEd448(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := CreateToken(testStruct, testEd448PrivateKey, SignatureTypeEd448)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTokenEd448(b *testing.B) {
	token, err := CreateToken(testStruct, testEd448PrivateKey, SignatureTypeEd448)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, err := VerifyToken[TestStruct](token, testEd448PrivateKey.Public())
		if err != nil {
			b.Fatal(err)
		}
	}
}

type TestStruct struct {
	A int    `msgpack:"a"`
	B string `msgpack:"b"`
}
