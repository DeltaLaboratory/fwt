package fwt

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const defaultCtx = "github.com/DeltaLaboratory/fwt"

// SignatureType is the type of signature.
type SignatureType int

// Signature types.
const (
	// SignatureTypeEd25519 is the signature type of Ed25519.
	SignatureTypeEd25519 SignatureType = iota
	// SignatureTypeEd448 is the signature type of Ed448.
	SignatureTypeEd448
	// SignatureTypeHMACSha256 is the signature type of HMAC-SHA256.
	SignatureTypeHMACSha256
	// SignatureTypeHMACSha512 is the signature type of HMAC-SHA512.
	SignatureTypeHMACSha512
	// SignatureTypeBlake2b256 is the signature type of blake2b-256.
	SignatureTypeBlake2b256
	// SignatureTypeBlake2b512 is the signature type of blake2b-512.
	SignatureTypeBlake2b512
	// SignatureTypeBlake3 is the signature type of blake3.
	SignatureTypeBlake3
)

var encoder cbor.EncMode
var decoder cbor.DecMode

func init() {
	var err error
	options := cbor.CanonicalEncOptions()

	encoder, err = options.EncMode()
	if err != nil {
		panic(err)
	}

	decodeOptions := cbor.DecOptions{}
	decodeOptions.UTF8 = cbor.UTF8DecodeInvalid
	decodeOptions.DupMapKey = cbor.DupMapKeyEnforcedAPF

	decoder, err = decodeOptions.DecMode()
	if err != nil {
		panic(err)
	}
}

// SetEncoder set custom cbor encoder.
func SetEncoder(enc cbor.EncMode) {
	encoder = enc
}

// SetDecoder set custom cbor decoder.
func SetDecoder(dec cbor.DecMode) {
	decoder = dec
}

// Signer is a token factory & signer.
type Signer struct {
	signatureType SignatureType
	signer        func([]byte) ([]byte, error)
	encryptor     func([]byte) ([]byte, error)
}

// NewSigner creates a new signer.
// signer is a function that takes a marshaled data and returns a signature.
// encryptor is an optional function that takes a token and returns an encrypted token.
// signatureType is the type of signature, must be matched with the signer.
func NewSigner(signer func([]byte) ([]byte, error), encryptor func([]byte) ([]byte, error), signatureType SignatureType) *Signer {
	return &Signer{
		signatureType: signatureType,
		signer:        signer,
		encryptor:     encryptor,
	}
}

// Sign signs the data and returns a signed token.
// If encryptor is set, the token will be encrypted.
func (s *Signer) Sign(data any) (string, error) {
	marshaled, err := encoder.Marshal(data)
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

// Verifier is a token verifier.
type Verifier struct {
	signatureType SignatureType
	verifier      func([]byte, []byte) error
	decrypter     func([]byte) ([]byte, error)
}

// NewVerifier creates a new verifier.
// verifier is a function that takes a marshaled data and a signature and returns an error if the signature is invalid.
// decrypter is an optional function that takes a token and returns a decrypted token.
// signatureType is the type of signature, must be matched with the verifier.
func NewVerifier(verifier func([]byte, []byte) error, decrypter func([]byte) ([]byte, error), signatureType SignatureType) *Verifier {
	return &Verifier{
		signatureType: signatureType,
		verifier:      verifier,
		decrypter:     decrypter,
	}
}

// Verify verifies the token.
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

	if marshaledLen < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	// check for overflow
	if 1+8+marshaledLen < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	if len(tokenDecoded) < 1+8+marshaledLen {
		return fmt.Errorf("invalid signature")
	}

	return v.verifier(tokenDecoded[1+8:1+8+marshaledLen], tokenDecoded[1+8+marshaledLen:])
}

// VerifyAndUnmarshal verifies the token and unmarshal the data into dst.
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

	if marshaledLen < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	if len(tokenDecoded) < 1+8+marshaledLen {
		return fmt.Errorf("invalid signature")
	}

	// check for overflow
	if 1+8+marshaledLen < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	if err := v.verifier(tokenDecoded[1+8:1+8+marshaledLen], tokenDecoded[1+8+marshaledLen:]); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if err := decoder.Unmarshal(tokenDecoded[1+8:1+8+marshaledLen], dst); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}
