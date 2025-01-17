package fwt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"testing"
	"time"

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

func TestMain(m *testing.M) {
	flag.Parse()

	m.Run()
}

func TestTokenOperations(t *testing.T) {
	tests := []struct {
		name      string
		signer    *Signer
		verifier  *Verifier
		shouldErr bool
	}{
		{
			name:     "XChaCha20Poly1305",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256ECB",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256CBC",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256CTR",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256GCM",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "Ed25519",
			signer:   NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519),
			verifier: NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519),
		},
		{
			name:     "Ed448",
			signer:   NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448),
			verifier: NewVerifier(NewEd448Verifier(testEd448PrivateKey.Public().(ed448.PublicKey)), nil, SignatureTypeEd448),
		},
		{
			name:     "HMACSha256",
			signer:   NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256),
			verifier: NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256),
		},
		{
			name:     "HMACSha512",
			signer:   NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512),
			verifier: NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512),
		},
		{
			name:     "Blake2b256",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256),
		},
		{
			name:     "Blake2b512",
			signer:   NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512),
			verifier: NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512),
		},
		{
			name:     "Blake3",
			signer:   NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3),
			verifier: NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3),
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
	benchmarks := []struct {
		name     string
		signer   *Signer
		verifier *Verifier
	}{
		{
			name:     "XChaCha20Poly1305",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewXChaCha20PolyEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewXChaCha20PolyDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256ECB",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESECBEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESECBDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256CBC",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCBCEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCBCDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256CTR",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESCTREncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESCTRDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "AES256GCM",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), NewAESGCMEncryptor(testEncryptionKey), SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), NewAESGCMDecrypter(testEncryptionKey), SignatureTypeBlake2b256),
		},
		{
			name:     "Ed25519",
			signer:   NewSigner(NewEd25519Signer(testEd25519PrivateKey), nil, SignatureTypeEd25519),
			verifier: NewVerifier(NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)), nil, SignatureTypeEd25519),
		},
		{
			name:     "Ed448",
			signer:   NewSigner(NewEd448Signer(testEd448PrivateKey), nil, SignatureTypeEd448),
			verifier: NewVerifier(NewEd448Verifier(testEd448PrivateKey.Public().(ed448.PublicKey)), nil, SignatureTypeEd448),
		},
		{
			name:     "HMACSha256",
			signer:   NewSigner(NewHMACSha256Signer(testHMACKey), nil, SignatureTypeHMACSha256),
			verifier: NewVerifier(NewHMACSha256Verifier(testHMACKey), nil, SignatureTypeHMACSha256),
		},
		{
			name:     "HMACSha512",
			signer:   NewSigner(NewHMACSha512Signer(testHMACKey), nil, SignatureTypeHMACSha512),
			verifier: NewVerifier(NewHMACSha512Verifier(testHMACKey), nil, SignatureTypeHMACSha512),
		},
		{
			name:     "Blake2b256",
			signer:   NewSigner(NewBlake2b256Signer(testHMACKey), nil, SignatureTypeBlake2b256),
			verifier: NewVerifier(NewBlake2b256Verifier(testHMACKey), nil, SignatureTypeBlake2b256),
		},
		{
			name:     "Blake2b512",
			signer:   NewSigner(NewBlake2b512Signer(testHMACKey), nil, SignatureTypeBlake2b512),
			verifier: NewVerifier(NewBlake2b512Verifier(testHMACKey), nil, SignatureTypeBlake2b512),
		},
		{
			name:     "Blake3",
			signer:   NewSigner(NewBlake3Signer(testHMACKey), nil, SignatureTypeBlake3),
			verifier: NewVerifier(NewBlake3Verifier(testHMACKey), nil, SignatureTypeBlake3),
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
	fmt.Printf("A: %d, B: %s, C: %s, D: %s", result.A, result.B, result.C.UTC().Format("2006-01-02"), result.D)
	// Output: A: 42, B: the answer to life, the universe and everything, C: 2009-11-10, D: some bytes
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
