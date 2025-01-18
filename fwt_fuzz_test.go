package fwt

import (
	"bytes"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"
)

func FuzzTokenOperations(f *testing.F) {
	// Add seed corpus
	f.Add(int64(42), "test string", []byte("test bytes"))

	// Fuzz test function
	f.Fuzz(func(t *testing.T, a int64, b string, d []byte) {
		// Create test struct with fuzzed data
		testData := TestStruct{
			A: int(a),
			B: b,
			C: time.Now(),
			D: d,
		}

		// Test different signer/verifier combinations
		signerConfigs := []struct {
			name            string
			signerFactory   SignerFactory
			verifierFactory VerifierFactory
		}{
			{
				name:            "Blake3",
				signerFactory:   NewBlake3Signer(testHMACKey),
				verifierFactory: NewBlake3Verifier(testHMACKey),
			},
			{
				name:            "Ed25519",
				signerFactory:   NewEd25519Signer(testEd25519PrivateKey),
				verifierFactory: NewEd25519Verifier(testEd25519PrivateKey.Public().(ed25519.PublicKey)),
			},
			{
				name:            "Blake2b256",
				signerFactory:   NewBlake2b256Signer(testHMACKey),
				verifierFactory: NewBlake2b256Verifier(testHMACKey),
			},
		}

		// Optional encryptors to test
		encryptors := []struct {
			name      string
			encryptor func([]byte) ([]byte, error)
			decrypter func([]byte) ([]byte, error)
		}{
			{
				name:      "NoEncryption",
				encryptor: nil,
				decrypter: nil,
			},
			{
				name:      "XChaCha20Poly1305",
				encryptor: NewXChaCha20PolyEncryptor(testEncryptionKey),
				decrypter: NewXChaCha20PolyDecrypter(testEncryptionKey),
			},
			{
				name:      "AESGCM",
				encryptor: NewAESGCMEncryptor(testEncryptionKey),
				decrypter: NewAESGCMDecrypter(testEncryptionKey),
			},
		}

		// Test each combination of signer and encryptor
		for _, sc := range signerConfigs {
			for _, ec := range encryptors {
				t.Run(sc.name+"/"+ec.name, func(t *testing.T) {
					// Create signer with optional encryption
					signer, err := NewSigner(sc.signerFactory, ec.encryptor)
					if err != nil {
						t.Skip("Signer creation failed")
					}

					// Create verifier with optional decryption
					verifier, err := NewVerifier(sc.verifierFactory, ec.decrypter)
					if err != nil {
						t.Skip("Verifier creation failed")
					}

					// Test signing
					token, err := signer.Sign(testData)
					if err != nil {
						return // Invalid input data, skip
					}

					// Test verification
					err = verifier.Verify(token)
					if err != nil {
						t.Logf("Verification failed: %v", err)
						return
					}

					// Test unmarshaling
					var result TestStruct
					err = verifier.VerifyAndUnmarshal(token, &result)
					if err != nil {
						t.Logf("Unmarshal failed: %v", err)
						return
					}

					// Verify unmarshaled data
					if result.A != testData.A ||
						result.B != testData.B ||
						!bytes.Equal(result.D, testData.D) {
						t.Errorf("Data mismatch after unmarshal")
					}
				})
			}
		}
	})
}

// Additional helper function to fuzz token verification directly
func FuzzTokenVerification(f *testing.F) {
	// Add seed corpus
	f.Add("BkikARgqAngvdGhlIGFuc3dlciB0byBsaWZlLCB0aGUgdW5pdmVyc2UgYW5kIGV2ZXJ5dGhpbmcDGkr58HAESnNvbWUgYnl0ZXMsbJnJZYZek95hXQommFdPRk0x_cpPMq850WOW3KUqgg")

	f.Fuzz(func(t *testing.T, token string) {
		verifier, err := NewVerifier(NewBlake3Verifier(testHMACKey), nil)
		if err != nil {
			t.Skip("Verifier creation failed")
		}

		// Test verification of potentially malformed tokens
		_ = verifier.Verify(token)

		// Test unmarshaling of potentially malformed tokens
		var result TestStruct
		_ = verifier.VerifyAndUnmarshal(token, &result)
	})
}
