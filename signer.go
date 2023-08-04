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

func NewEd25519Signer(key ed25519.PrivateKey) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		return ed25519.Sign(key, data), nil
	}
}

func NewEd25519Verifier(key ed25519.PublicKey) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		if ed25519.Verify(key, data, sig) {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

func NewEd448Signer(key ed448.PrivateKey) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		return ed448.Sign(key, data, "github.com/DeltaLaboratory/mwt"), nil
	}
}

func NewEd448Verifier(key ed448.PublicKey) func([]byte, []byte) error {
	return func(data []byte, sig []byte) error {
		if ed448.Verify(key, data, sig, "github.com/DeltaLaboratory/mwt") {
			return nil
		}
		return fmt.Errorf("invalid signature")
	}
}

func NewHMACSha256Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher := hmac.New(sha256.New, key)
		hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

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

func NewHMACSha512Signer(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		hasher := hmac.New(sha512.New, key)
		hasher.Write(data)
		return hasher.Sum(nil), nil
	}
}

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
