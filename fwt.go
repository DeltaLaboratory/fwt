package fwt

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/DeltaLaboratory/fwt/internal"
)

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
	options := cbor.CanonicalEncOptions()
	encoder, _ = options.EncMode()

	decodeOptions := cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
		UTF8:        cbor.UTF8DecodeInvalid,
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	}
	decoder, _ = decodeOptions.DecMode()
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
	encryptor     EncryptorFunc
}

// NewSigner creates a new signer.
// signer is a function that takes a marshaled data and returns a signature.
// encryptor is an optional function that takes a token and returns an encrypted token.
// signatureType is the type of signature, must be matched with the signer.
func NewSigner(signer SignerFactory, encryptor EncryptorFactory) (*Signer, error) {
	sig, signerFunc, err := signer()
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	if encryptor == nil {
		return &Signer{
			signatureType: sig,
			signer:        signerFunc,
			encryptor:     nil,
		}, nil
	}

	encryptorFunc, err := encryptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Signer{
		signatureType: sig,
		signer:        signerFunc,
		encryptor:     encryptorFunc,
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
	decrypter     DecrypterFunc
}

// NewVerifier creates a new verifier.
// verifier is a function that takes a marshaled data and a signature and returns an error if the signature is invalid.
// decrypter is an optional function that takes a token and returns a decrypted token.
// signatureType is the type of signature, must be matched with the verifier.
func NewVerifier(verifier VerifierFactory, decrypter DecrypterFactory) (*Verifier, error) {
	sig, verifierFunc, err := verifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	if decrypter == nil {
		return &Verifier{
			signatureType: sig,
			verifier:      verifierFunc,
			decrypter:     nil,
		}, nil
	}

	decrypterFunc, err := decrypter()
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypter: %w", err)
	}

	return &Verifier{
		signatureType: sig,
		verifier:      verifierFunc,
		decrypter:     decrypterFunc,
	}, nil
}

// decodeToken decodes token and returns decoded token, VLQ boundary, token boundary.
func (v *Verifier) decodeToken(token string) ([]byte, int, int, error) {
	tokenDecoded := internal.Alloc(base64Encoder.DecodedLen(len(token)))
	tokenDecodedLength, err := base64Encoder.Decode(tokenDecoded, []byte(token))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode token: %w", err)
	}
	tokenDecoded = tokenDecoded[:tokenDecodedLength]

	if v.decrypter != nil {
		decrypted, err := v.decrypter(tokenDecoded)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed to decrypt data: %w", err)
		}
		tokenDecoded = decrypted
	}

	if len(tokenDecoded) < 3 {
		return nil, 0, 0, fmt.Errorf("invalid token: too short")
	}

	sigType := SignatureType(tokenDecoded[0])
	if sigType != v.signatureType {
		return nil, 0, 0, fmt.Errorf("invalid token: invalid signature type: allowed %d, got %d", v.signatureType, sigType)
	}

	marshaledLen, vlqLength, err := decodeVLQ(tokenDecoded[1:])
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode VLQ: %w", err)
	}

	if marshaledLen < 0 {
		return nil, 0, 0, fmt.Errorf("invalid token: invalid marshaled length: %d", marshaledLen)
	}

	tokenLength := 1 + vlqLength + int(marshaledLen)

	if len(tokenDecoded) < tokenLength {
		return nil, 0, 0, fmt.Errorf("invalid signature")
	}

	return tokenDecoded, vlqLength, tokenLength, nil
}

// Verify verifies the token.
func (v *Verifier) Verify(token string) error {
	tokenDecoded, vlqLength, tokenLength, err := v.decodeToken(token)
	if err != nil {
		return err
	}

	return v.verifier(tokenDecoded[1+vlqLength:tokenLength], tokenDecoded[tokenLength:])
}

// VerifyAndUnmarshal verifies the token and unmarshal the data into dst.
func (v *Verifier) VerifyAndUnmarshal(token string, dst any) error {
	tokenDecoded, vlqLength, tokenLength, err := v.decodeToken(token)
	if err != nil {
		return err
	}

	if err := v.verifier(tokenDecoded[1+vlqLength:tokenLength], tokenDecoded[tokenLength:]); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if err := decoder.Unmarshal(tokenDecoded[1+vlqLength:tokenLength], dst); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}
