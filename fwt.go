package fwt

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/DeltaLaboratory/fwt/internal"
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

var base64Encoder = base64.RawURLEncoding

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
	signer        SignerFunc
	encryptor     func([]byte) ([]byte, error)
}

// NewSigner creates a new signer.
// signer is a function that takes a marshaled data and returns a signature.
// encryptor is an optional function that takes a token and returns an encrypted token.
// signatureType is the type of signature, must be matched with the signer.
func NewSigner(signer SignerFactory, encryptor func([]byte) ([]byte, error)) (*Signer, error) {
	sig, signerFunc, err := signer()
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &Signer{
		signatureType: sig,
		signer:        signerFunc,
		encryptor:     encryptor,
	}, nil
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

	// allocate token type + VLQ Max Length + marshaled length + signature length
	token := internal.Alloc(1 + 9 + len(marshaled) + len(signature))
	token[0] = byte(s.signatureType)

	vlqLength, err := encodeVLQ(token[1:], uint64(len(marshaled)))
	if err != nil {
		return "", fmt.Errorf("failed to encode VLQ: %w", err)
	}

	copy(token[1+vlqLength:], marshaled)
	copy(token[1+vlqLength+len(marshaled):], signature)

	if s.encryptor != nil {
		encrypted, err := s.encryptor(token[:1+vlqLength+len(marshaled)+len(signature)])
		if err != nil {
			return "", fmt.Errorf("failed to encrypt data: %w", err)
		}
		return base64Encoder.EncodeToString(encrypted), nil
	}
	return base64Encoder.EncodeToString(token[:1+vlqLength+len(marshaled)+len(signature)]), err
}

// Verifier is a token verifier.
type Verifier struct {
	signatureType SignatureType
	verifier      VerifierFunc
	decrypter     func([]byte) ([]byte, error)
}

// NewVerifier creates a new verifier.
// verifier is a function that takes a marshaled data and a signature and returns an error if the signature is invalid.
// decrypter is an optional function that takes a token and returns a decrypted token.
// signatureType is the type of signature, must be matched with the verifier.
func NewVerifier(verifier VerifierFactory, decrypter func([]byte) ([]byte, error)) (*Verifier, error) {
	sig, verifierFunc, err := verifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &Verifier{
		signatureType: sig,
		verifier:      verifierFunc,
		decrypter:     decrypter,
	}, nil
}

// Verify verifies the token.
func (v *Verifier) Verify(token string) error {
	tokenDecoded := internal.Alloc(base64Encoder.DecodedLen(len(token)))
	tokenDecodedLength, err := base64Encoder.Decode(tokenDecoded, []byte(token))
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}
	tokenDecoded = tokenDecoded[:tokenDecodedLength]

	if v.decrypter != nil {
		decrypted, err := v.decrypter(tokenDecoded)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}
		tokenDecoded = decrypted
	}

	if len(tokenDecoded) < 3 {
		return fmt.Errorf("invalid token: too short")
	}

	sigType := SignatureType(tokenDecoded[0])
	if sigType != v.signatureType {
		return fmt.Errorf("invalid token: invalid signature type: allowed %d, got %d", v.signatureType, sigType)
	}

	marshaledLen, vlqLength, err := decodeVLQ(tokenDecoded[1:])
	if err != nil {
		return fmt.Errorf("failed to decode VLQ: %w", err)
	}

	if marshaledLen < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	tokenLength := 1 + vlqLength + int(marshaledLen)

	// check for overflow
	if tokenLength < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	if len(tokenDecoded) < tokenLength {
		return fmt.Errorf("invalid signature")
	}

	return v.verifier(tokenDecoded[1+vlqLength:tokenLength], tokenDecoded[tokenLength:])
}

// VerifyAndUnmarshal verifies the token and unmarshal the data into dst.
func (v *Verifier) VerifyAndUnmarshal(token string, dst any) error {
	tokenDecoded := internal.Alloc(base64Encoder.DecodedLen(len(token)))
	tokenDecodedLength, err := base64Encoder.Decode(tokenDecoded, []byte(token))
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}
	tokenDecoded = tokenDecoded[:tokenDecodedLength]

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

	marshaledLen, vlqLength, err := decodeVLQ(tokenDecoded[1:])
	if err != nil {
		return fmt.Errorf("failed to decode VLQ: %w", err)
	}

	if marshaledLen < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	tokenLength := 1 + vlqLength + int(marshaledLen)

	if len(tokenDecoded) < tokenLength {
		return fmt.Errorf("invalid signature")
	}

	// check for overflow
	if tokenLength < 0 {
		return fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	if err := v.verifier(tokenDecoded[1+vlqLength:tokenLength], tokenDecoded[tokenLength:]); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if err := decoder.Unmarshal(tokenDecoded[1+vlqLength:tokenLength], dst); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}
