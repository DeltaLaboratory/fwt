package fwt

import (
	"encoding/hex"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

var testHMACKey = must(hex.DecodeString("f14838bdddcd9a83af030419a1e9be8af10f561147159f966a910c71f42122bf"))
var testEncryptionKey = must(hex.DecodeString("7b533a9456a027d983495ffc8d0bdc829c50df1ac12bbecce39620e08912c9c6"))
var testEd25519PrivateKey ed25519.PrivateKey = must(hex.DecodeString("878a640371274e6d93ab6b6c99f4126b878a640371274e6d93ab6b6c99f4126b"))
var testEd448PrivateKey ed448.PrivateKey = must(hex.DecodeString("061082d36ba67fd1de4a632e66adc333c495bed70000f9c938abd8714bdf9a7db10256696f06a0709497197d16e5695c671025730cac67ceae"))

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

var testStruct = TestStruct{
	A: 42,
	B: "the answer to life, the universe and everything",
	C: time.Unix(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC).Unix(), 0),
	D: []byte("some bytes"),
}

func TestMain(m *testing.M) {
	flag.Parse()

	m.Run()
}

func TestTokenOperations(t *testing.T) {
	tests := []struct {
		name      string
		signer    *Signer
		verifier  *Verifier
		setupErr  bool
		shouldErr bool
	}{
		{
			name: "XChaCha20Poly1305",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "AES256ECB",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "AES256CBC",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "AES256CTR",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "AES256GCM",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "Ed25519",
			signer: func() *Signer {
				s, err := NewSigner(NewEd25519Signer(testEd25519PrivateKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewEd25519Verifier(ed25519.NewKeyFromSeed(testEd25519PrivateKey).Public().(ed25519.PublicKey)), nil)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "Ed448",
			signer: func() *Signer {
				s, err := NewSigner(NewEd448Signer(testEd448PrivateKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewEd448Verifier(ed448.NewKeyFromSeed(testEd448PrivateKey).Public().(ed448.PublicKey)), nil)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "HMACSha256",
			signer: func() *Signer {
				s, err := NewSigner(NewHMACSha256Signer(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewHMACSha256Verifier(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "HMACSha512",
			signer: func() *Signer {
				s, err := NewSigner(NewHMACSha512Signer(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewHMACSha512Verifier(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "Blake2b256",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b256Signer(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b256Verifier(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "Blake2b512",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake2b512Signer(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake2b512Verifier(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
		{
			name: "Blake3",
			signer: func() *Signer {
				s, err := NewSigner(NewBlake3Signer(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}(),
			verifier: func() *Verifier {
				v, err := NewVerifier(NewBlake3Verifier(testHMACKey))
				if err != nil {
					t.Fatal(err)
				}
				return v
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/Create", func(t *testing.T) {
			_, err := tt.signer.Sign(testStruct)
			if (err != nil) != tt.shouldErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.shouldErr)
			}
		})

		t.Run(tt.name+"/Verify", func(t *testing.T) {
			token, err := tt.signer.Sign(testStruct)
			if (err != nil) != tt.shouldErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.shouldErr)
				return
			}

			if err := tt.verifier.Verify(token); (err != nil) != tt.shouldErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.shouldErr)
			}
		})

		t.Run(tt.name+"/VerifyAndUnmarshal", func(t *testing.T) {
			token, err := tt.signer.Sign(testStruct)
			if (err != nil) != tt.shouldErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.shouldErr)
				return
			}

			result := new(TestStruct)
			if err := tt.verifier.VerifyAndUnmarshal(token, result); (err != nil) != tt.shouldErr {
				t.Errorf("VerifyAndUnmarshal() error = %v, wantErr %v", err, tt.shouldErr)
				return
			}

			if !tt.shouldErr {
				if result.A != testStruct.A {
					t.Errorf("VerifyAndUnmarshal() got A = %v, want %v", result.A, testStruct.A)
				}
				if result.B != testStruct.B {
					t.Errorf("VerifyAndUnmarshal() got B = %v, want %v", result.B, testStruct.B)
				}
			}
		})
	}
}

func BenchmarkTokenOperations(b *testing.B) {
	initSigner := func(signer func() (*Signer, error)) *Signer {
		s, err := signer()
		if err != nil {
			b.Fatal(err)
		}
		return s
	}

	initVerifier := func(verifier func() (*Verifier, error)) *Verifier {
		v, err := verifier()
		if err != nil {
			b.Fatal(err)
		}
		return v
	}

	benchmarks := []struct {
		name     string
		signer   *Signer
		verifier *Verifier
	}{
		{
			name: "XChaCha20Poly1305",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey))
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey))
			}),
		},
		{
			name: "AES256ECB",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey))
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey))
			}),
		},
		{
			name: "AES256CBC",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey))
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey))
			}),
		},
		{
			name: "AES256CTR",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey))
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey))
			}),
		},
		{
			name: "AES256GCM",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey))
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey))
			}),
		},
		{
			name: "Ed25519",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewEd25519Verifier(ed25519.NewKeyFromSeed(testEd25519PrivateKey).Public().(ed25519.PublicKey)), nil)
			}),
		},
		{
			name: "Ed448",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewEd448Signer(testEd448PrivateKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewEd448Verifier(ed448.NewKeyFromSeed(testEd448PrivateKey).Public().(ed448.PublicKey)), nil)
			}),
		},
		{
			name: "HMACSha256",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewHMACSha256Signer(testHMACKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewHMACSha256Verifier(testHMACKey), nil)
			}),
		},
		{
			name: "HMACSha512",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewHMACSha512Signer(testHMACKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewHMACSha512Verifier(testHMACKey), nil)
			}),
		},
		{
			name: "Blake2b256",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b256Signer(testHMACKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b256Verifier(testHMACKey), nil)
			}),
		},
		{
			name: "Blake2b512",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake2b512Signer(testHMACKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake2b512Verifier(testHMACKey), nil)
			}),
		},
		{
			name: "Blake3",
			signer: initSigner(func() (*Signer, error) {
				return NewSigner(NewBlake3Signer(testHMACKey), nil)
			}),
			verifier: initVerifier(func() (*Verifier, error) {
				return NewVerifier(NewBlake3Verifier(testHMACKey), nil)
			}),
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name+"/Create", func(b *testing.B) {
			b.StopTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				_, err := bm.signer.Sign(testStruct)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(bm.name+"/Verify", func(b *testing.B) {
			b.StopTimer()
			token, err := bm.signer.Sign(testStruct)
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				if err := bm.verifier.Verify(token); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(bm.name+"/VerifyAndUnmarshal", func(b *testing.B) {
			b.StopTimer()
			token, err := bm.signer.Sign(testStruct)
			if err != nil {
				b.Fatal(err)
			}
			result := new(TestStruct)
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				if err := bm.verifier.VerifyAndUnmarshal(token, result); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func ExampleSigner_Sign() {
	HMACKey := []byte("00000000000000000000000000000000")
	signer, err := NewSigner(NewBlake3Signer(HMACKey), nil)
	if err != nil {
		panic(err)
	}
	token, err := signer.Sign(testStruct)
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
	// Output: BkikARgqAngvdGhlIGFuc3dlciB0byBsaWZlLCB0aGUgdW5pdmVyc2UgYW5kIGV2ZXJ5dGhpbmcDGkr58HAESnNvbWUgYnl0ZXMsbJnJZYZek95hXQommFdPRk0x_cpPMq850WOW3KUqgg
}

func ExampleVerifier_Verify() {
	HMACKey := []byte("00000000000000000000000000000000")
	verifier, err := NewVerifier(NewBlake3Verifier(HMACKey), nil)
	if err != nil {
		panic(err)
	}
	if err := verifier.Verify("BkikARgqAngvdGhlIGFuc3dlciB0byBsaWZlLCB0aGUgdW5pdmVyc2UgYW5kIGV2ZXJ5dGhpbmcDGkr58HAESnNvbWUgYnl0ZXMsbJnJZYZek95hXQommFdPRk0x_cpPMq850WOW3KUqgg"); err != nil {
		panic(err)
	}
	fmt.Println("token is valid")
	// Output: token is valid
}

func ExampleVerifier_VerifyAndUnmarshal() {
	HMACKey := []byte("00000000000000000000000000000000")
	verifier, err := NewVerifier(NewBlake3Verifier(HMACKey), nil)
	if err != nil {
		panic(err)
	}
	result := new(TestStruct)
	if err := verifier.VerifyAndUnmarshal("BkikARgqAngvdGhlIGFuc3dlciB0byBsaWZlLCB0aGUgdW5pdmVyc2UgYW5kIGV2ZXJ5dGhpbmcDGkr58HAESnNvbWUgYnl0ZXMsbJnJZYZek95hXQommFdPRk0x_cpPMq850WOW3KUqgg", result); err != nil {
		panic(err)
	}
	fmt.Printf("A: %d, B: %s, C: %s, D: %s", result.A, result.B, result.C.UTC().Format("2006-01-02"), result.D)
	// Output: A: 42, B: the answer to life, the universe and everything, C: 2009-11-10, D: some bytes
}

// TODO: reimplement fuzzer correctly

type TestStruct struct {
	A int       `cbor:"1,keyasint"`
	B string    `cbor:"2,keyasint"`
	C time.Time `cbor:"3,keyasint"`
	D []byte    `cbor:"4,keyasint"`
}
