package fwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

type SignerFactory func() (SignatureType, SignerFunc, error)
type SignerFunc func([]byte) ([]byte, error)

type VerifierFactory func() (SignatureType, VerifierFunc, error)
type VerifierFunc func([]byte, []byte) error

// NewEd25519Signer creates a new signer using Ed25519 with 32 bytes seed.
func NewEd25519Signer(key []byte) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		if len(key) != ed25519.SeedSize {
			return SignatureTypeEd25519, nil, fmt.Errorf("invalid key size")
		}
		edKey := ed25519.NewKeyFromSeed(key)

		return SignatureTypeEd25519, func(data []byte) ([]byte, error) {
			return ed25519.Sign(edKey, data), nil
		}, nil
	}
}

// NewEd25519Verifier creates a new verifier using Ed25519 with ed25519.PublicKey
func NewEd25519Verifier(key []byte) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		if len(key) != ed25519.PublicKeySize {
			return SignatureTypeEd25519, nil, fmt.Errorf("invalid key size")
		}

		edKey := ed25519.PublicKey(key)

		return SignatureTypeEd25519, func(data []byte, sig []byte) error {
			if ed25519.Verify(edKey, data, sig) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}

// NewEd448Signer creates a new signer using Ed448 with ed448.PrivateKey.
// context is optional and defaults to empty string.
// please refer to https://tools.ietf.org/html/rfc8032#section-5.2.6 for more information.
func NewEd448Signer(key []byte, context ...string) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		if len(key) != ed448.SeedSize {
			return SignatureTypeEd448, nil, fmt.Errorf("invalid key size")
		}

		var ctx string
		if len(context) != 0 {
			ctx = context[0]

			if len(ctx) > ed448.ContextMaxSize {
				return SignatureTypeEd448, nil, fmt.Errorf("invalid context size")
			}
		}

		edKey := ed448.NewKeyFromSeed(key)

		return SignatureTypeEd448, func(data []byte) ([]byte, error) {
			return ed448.Sign(edKey, data, ctx), nil
		}, nil
	}
}

// NewEd448Verifier creates a new verifier using Ed448 with ed448.PublicKey.
// context is optional and defaults to empty string.
// please refer to https://tools.ietf.org/html/rfc8032#section-5.2.6 for more information.
func NewEd448Verifier(key []byte, context ...string) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		if len(key) != ed448.PublicKeySize {
			return SignatureTypeEd448, nil, fmt.Errorf("invalid key size")
		}

		var ctx string
		if len(context) != 0 {
			ctx = context[0]

			if len(ctx) > ed448.ContextMaxSize {
				return SignatureTypeEd448, nil, fmt.Errorf("invalid context size")
			}
		}

		edKey := ed448.PublicKey(key)

		return SignatureTypeEd448, func(data []byte, sig []byte) error {
			if ed448.Verify(edKey, data, sig, ctx) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}

// NewHMACSha256Signer creates a new signer using HMAC-SHA256 with a key.
func NewHMACSha256Signer(key []byte) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		return SignatureTypeHMACSha256, func(data []byte) ([]byte, error) {
			hasher := hmac.New(sha256.New, key)
			hasher.Write(data)
			return hasher.Sum(nil), nil
		}, nil
	}
}

// NewHMACSha256Verifier creates a new verifier using HMAC-SHA256 with a key.
func NewHMACSha256Verifier(key []byte) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		return SignatureTypeHMACSha256, func(data []byte, sig []byte) error {
			hasher := hmac.New(sha256.New, key)
			hasher.Write(data)
			if hmac.Equal(hasher.Sum(nil), sig) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}

// NewHMACSha512Signer creates a new signer using HMAC-SHA512 with a key.
func NewHMACSha512Signer(key []byte) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		return SignatureTypeHMACSha512, func(data []byte) ([]byte, error) {
			hasher := hmac.New(sha512.New, key)
			hasher.Write(data)
			return hasher.Sum(nil), nil
		}, nil
	}
}

// NewHMACSha512Verifier creates a new verifier using HMAC-SHA512 with a key.
func NewHMACSha512Verifier(key []byte) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		return SignatureTypeHMACSha512, func(data []byte, sig []byte) error {
			hasher := hmac.New(sha512.New, key)
			hasher.Write(data)
			if hmac.Equal(hasher.Sum(nil), sig) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}

// NewBlake2b256Signer creates a new signer using blake2b-256 with a key.
func NewBlake2b256Signer(key []byte) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		if len(key) > blake2b.Size {
			return SignatureTypeBlake2b256, nil, fmt.Errorf("invalid key size")
		}

		return SignatureTypeBlake2b256, func(data []byte) ([]byte, error) {
			hasher, err := blake2b.New256(key)
			if err != nil {
				return nil, fmt.Errorf("failed to create blake2b-256 hasher: %w", err)
			}
			hasher.Write(data)
			return hasher.Sum(nil), nil
		}, nil
	}
}

// NewBlake2b256Verifier creates a new verifier using blake2b-256 with a key.
func NewBlake2b256Verifier(key []byte) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		if len(key) > blake2b.Size {
			t := blake2b.Sum512(key)
			key = t[:]
		}

		return SignatureTypeBlake2b256, func(data []byte, sig []byte) error {
			hasher, err := blake2b.New256(key)
			if err != nil {
				return fmt.Errorf("failed to create blake2b-256 hasher: %w", err)
			}
			hasher.Write(data)
			if hmac.Equal(hasher.Sum(nil), sig) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}

// NewBlake2b512Signer creates a new signer using blake2b-512 with a key.
func NewBlake2b512Signer(key []byte) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		if len(key) > blake2b.Size {
			return SignatureTypeBlake2b512, nil, fmt.Errorf("invalid key size")
		}

		return SignatureTypeBlake2b512, func(data []byte) ([]byte, error) {
			hasher, err := blake2b.New512(key)
			if err != nil {
				return nil, fmt.Errorf("failed to create blake2b-512 hasher: %w", err)
			}
			hasher.Write(data)
			return hasher.Sum(nil), nil
		}, nil
	}
}

// NewBlake2b512Verifier creates a new verifier using blake2b-512 with a key.
func NewBlake2b512Verifier(key []byte) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		if len(key) > blake2b.Size {
			return SignatureTypeBlake2b512, nil, fmt.Errorf("invalid key size")
		}

		return SignatureTypeBlake2b512, func(data []byte, sig []byte) error {
			hasher, err := blake2b.New512(key)
			if err != nil {
				return fmt.Errorf("failed to create blake2b-512 hasher: %w", err)
			}
			hasher.Write(data)
			if hmac.Equal(hasher.Sum(nil), sig) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}

// NewBlake3Signer creates a new signer using blake3 with a key.
func NewBlake3Signer(key []byte) SignerFactory {
	return func() (SignatureType, SignerFunc, error) {
		if len(key) != 32 {
			return SignatureTypeBlake3, nil, fmt.Errorf("invalid key size")
		}

		return SignatureTypeBlake3, func(data []byte) ([]byte, error) {
			hasher, err := blake3.NewKeyed(key)
			if err != nil {
				return nil, fmt.Errorf("failed to create blake3 hasher: %w", err)
			}
			_, _ = hasher.Write(data)
			return hasher.Sum(nil), nil
		}, nil
	}
}

// NewBlake3Verifier creates a new verifier using blake3 with a key.
func NewBlake3Verifier(key []byte) VerifierFactory {
	return func() (SignatureType, VerifierFunc, error) {
		if len(key) != 32 {
			return SignatureTypeBlake3, nil, fmt.Errorf("invalid key size")
		}

		return SignatureTypeBlake3, func(data []byte, sig []byte) error {
			hasher, err := blake3.NewKeyed(key)
			if err != nil {
				return fmt.Errorf("failed to create blake3 hasher: %w", err)
			}
			_, _ = hasher.Write(data)
			if hmac.Equal(hasher.Sum(nil), sig) {
				return nil
			}
			return fmt.Errorf("invalid signature")
		}, nil
	}
}
