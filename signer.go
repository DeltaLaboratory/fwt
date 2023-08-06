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

// NewEd25519Signer creates a new signer using Ed25519 with ed25519.PrivateKey.
func NewEd25519Signer(key ed25519.PrivateKey) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		return ed25519.Sign(key, data), nil
	}
}

// NewEd25519Verifier creates a new verifier using Ed25519 with ed25519.PublicKey
func NewEd25519Verifier(key ed25519.PublicKey) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		if ed25519.Verify(key, data, sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

// NewEd448Signer creates a new signer using Ed448 with ed448.PrivateKey.
// context is optional and defaults to "github.com/DeltaLaboratory/mwt".
// please refer to https://tools.ietf.org/html/rfc8032#section-5.2.6 for more information.
func NewEd448Signer(key ed448.PrivateKey, context ...string) func([]byte) ([]byte, error) {
	var ctx string
	if len(context) != 0 {
		ctx = context[0]
	} else {
		ctx = "github.com/DeltaLaboratory/mwt"
	}
	return func(data []byte) ([]byte, error) {
		return ed448.Sign(key, data, ctx), nil
	}
}

// NewEd448Verifier creates a new verifier using Ed448 with ed448.PublicKey.
// context is optional and defaults to "github.com/DeltaLaboratory/mwt".
// please refer to https://tools.ietf.org/html/rfc8032#section-5.2.6 for more information.
func NewEd448Verifier(key ed448.PublicKey, context ...string) func([]byte, []byte) error {
	var ctx string
	if len(context) != 0 {
		ctx = context[0]
	} else {
		ctx = "github.com/DeltaLaboratory/mwt"
	}
	return func(data []byte, sig []byte) error {
		if ed448.Verify(key, data, sig, ctx) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

// NewHMACSha256Signer creates a new signer using HMAC-SHA256 with key.
func NewHMACSha256Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher := hmac.New(sha256.New, key)
		hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

// NewHMACSha256Verifier creates a new verifier using HMAC-SHA256 with key.
func NewHMACSha256Verifier(key []byte) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		hasher := hmac.New(sha256.New, key)
		hasher.Write(data)
		if hmac.Equal(hasher.Sum(nil), sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

// NewHMACSha512Signer creates a new signer using HMAC-SHA512 with key.
func NewHMACSha512Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher := hmac.New(sha512.New, key)
		hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

// NewHMACSha512Verifier creates a new verifier using HMAC-SHA512 with key.
func NewHMACSha512Verifier(key []byte) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		hasher := hmac.New(sha512.New, key)
		hasher.Write(data)
		if hmac.Equal(hasher.Sum(nil), sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

// NewBlake2b256Signer creates a new signer using blake2b-256 with key.
func NewBlake2b256Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher, err := blake2b.New256(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create blake2b-256 hasher: %w", err)
		}
		hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

// NewBlake2b256Verifier creates a new verifier using blake2b-256 with key.
func NewBlake2b256Verifier(key []byte) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		hasher, err := blake2b.New256(key)
		if err != nil {
			return fmt.Errorf("failed to create blake2b-256 hasher: %w", err)
		}
		hasher.Write(data)
		if hmac.Equal(hasher.Sum(nil), sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

// NewBlake2b512Signer creates a new signer using blake2b-512 with key.
func NewBlake2b512Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher, err := blake2b.New512(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create blake2b-512 hasher: %w", err)
		}
		hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

// NewBlake2b512Verifier creates a new verifier using blake2b-512 with key.
func NewBlake2b512Verifier(key []byte) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		hasher, err := blake2b.New512(key)
		if err != nil {
			return fmt.Errorf("failed to create blake2b-512 hasher: %w", err)
		}
		hasher.Write(data)
		if hmac.Equal(hasher.Sum(nil), sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

// NewBlake3Signer creates a new signer using blake3 with key.
func NewBlake3Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher, err := blake3.NewKeyed(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create blake3 hasher: %w", err)
		}
		_, _ = hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

// NewBlake3Verifier creates a new verifier using blake3 with key.
func NewBlake3Verifier(key []byte) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		hasher, err := blake3.NewKeyed(key)
		if err != nil {
			return fmt.Errorf("failed to create blake3 hasher: %w", err)
		}
		_, _ = hasher.Write(data)
		if hmac.Equal(hasher.Sum(nil), sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}
