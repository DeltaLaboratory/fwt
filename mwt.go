package mwt

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor"
)

type SignatureType int

const (
	SignatureTypeEd25519 SignatureType = iota
	SignatureTypeEd448
	SignatureTypeHMACSha256
	SignatureTypeHMACSha512
	SignatureTypeBlake2b256
	SignatureTypeBlake2b512
	SignatureTypeBlake3
)

type Signer struct {
	signatureType SignatureType
	signer        func([]byte) ([]byte, error)
	encryptor     func([]byte) ([]byte, error)
}

func NewSigner(signer func([]byte) ([]byte, error), encryptor func([]byte) ([]byte, error), signatureType SignatureType) *Signer {
	return &Signer{
		signatureType: signatureType,
		signer:        signer,
		encryptor:     encryptor,
	}
}

func (s *Signer) Sign(data any) (string, error) {
	marshaled, err := cbor.Marshal(data, cbor.CanonicalEncOptions())
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	signature, err := s.signer(marshaled)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	token := make([]byte, 1+8+len(marshaled)+len(signature))
	token[0] = byte(s.signatureType)
	for i := 0; i < 8; i++ {
		token[1+i] = byte(len(marshaled) >> (8 * i))
	}
	copy(token[1+8:], marshaled)
	copy(token[1+8+len(marshaled):], signature)

	if s.encryptor != nil {
		encrypted, err := s.encryptor(token)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt data: %w", err)
		}
		return base64.StdEncoding.EncodeToString(encrypted), nil
	}
	return base64.StdEncoding.EncodeToString(token), err
}

type Verifier struct {
	signatureType SignatureType
	verifier      func([]byte, []byte) error
	decrypter     func([]byte) ([]byte, error)
}

func NewVerifier(verifier func([]byte, []byte) error, decrypter func([]byte) ([]byte, error), signatureType SignatureType) *Verifier {
	return &Verifier{
		signatureType: signatureType,
		verifier:      verifier,
		decrypter:     decrypter,
	}
}

func (v *Verifier) Verify(token string) error {
	tokenDecoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}

	if v.decrypter != nil {
		decrypted, err := v.decrypter(tokenDecoded)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}
		tokenDecoded = decrypted
	}

	if len(tokenDecoded) < 9 {
		return fmt.Errorf("invalid token: too short")
	}
	sigType := SignatureType(tokenDecoded[0])
	if sigType != v.signatureType {
		return fmt.Errorf("invalid token: invalid signature type: allowed %d, got %d", v.signatureType, sigType)
	}
	marshaledLen := 0
	for i := 0; i < 8; i++ {
		marshaledLen |= int(tokenDecoded[1+i]) << (8 * i)
	}

	if len(tokenDecoded) < 1+8+marshaledLen {
		return fmt.Errorf("invalid signature")
	}

	return v.verifier(tokenDecoded[1+8:1+8+marshaledLen], tokenDecoded[1+8+marshaledLen:])
}

func (v *Verifier) VerifyAndUnmarshal(token string, dst any) error {
	tokenDecoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}

	if v.decrypter != nil {
		decrypted, err := v.decrypter(tokenDecoded)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}
		tokenDecoded = decrypted
	}

	if len(tokenDecoded) < 9 {
		return fmt.Errorf("invalid token: too short")
	}
	sigType := SignatureType(tokenDecoded[0])
	if sigType != v.signatureType {
		return fmt.Errorf("invalid token: invalid signature type")
	}
	marshaledLen := 0
	for i := 0; i < 8; i++ {
		marshaledLen |= int(tokenDecoded[1+i]) << (8 * i)
	}

	if len(tokenDecoded) < 1+8+marshaledLen {
		return fmt.Errorf("invalid signature")
	}

	if err := v.verifier(tokenDecoded[1+8:1+8+marshaledLen], tokenDecoded[1+8+marshaledLen:]); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if err := cbor.Unmarshal(tokenDecoded[1+8:1+8+marshaledLen], dst); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}
