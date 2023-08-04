package mwt

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/vmihailenco/msgpack/v5"
)

type SignatureType int

const (
	SignatureTypeEd25519 SignatureType = iota
	SignatureTypeEd448
)

func CreateToken[T any](data T, pk []byte, sigType SignatureType) (string, error) {
	marshaled, err := msgpack.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	var signature []byte
	switch sigType {
	case SignatureTypeEd25519:
		signature = ed25519.Sign(pk, marshaled)
	case SignatureTypeEd448:
		signature = ed448.Sign(pk, marshaled, "github.com/DeltaLaboratory/mwt")
	default:
		return "", fmt.Errorf("invalid signature type")
	}

	result := make([]byte, 1+8+len(marshaled)+len(signature))

	result[0] = byte(sigType)
	for i := 0; i < 8; i++ {
		result[1+i] = byte(len(marshaled) >> (8 * i))
	}
	copy(result[9:9+len(marshaled)], marshaled)
	copy(result[9+len(marshaled):], signature)
	return base64.StdEncoding.EncodeToString(result), nil
}

func VerifyToken[T any](token string, pubKey crypto.PublicKey) (*T, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}
	if len(decoded) < 9 {
		return nil, fmt.Errorf("invalid token: invalid length")
	}
	dataLength := 0
	for i := 0; i < 8; i++ {
		dataLength |= int(decoded[1+i]) << (8 * i)
	}

	switch decoded[0] {
	case byte(SignatureTypeEd25519):
		if len(decoded) != 9+dataLength+ed25519.SignatureSize {
			return nil, fmt.Errorf("invalid token: invalid length")
		}
		pk, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid token: invalid public key type: required ed25519.PublicKey")
		}
		if !ed25519.Verify(pk, decoded[9:9+dataLength], decoded[9+dataLength:]) {
			return nil, fmt.Errorf("invalid token: invalid signature")
		}
	case byte(SignatureTypeEd448):
		if len(decoded) != 9+dataLength+ed448.SignatureSize {
			return nil, fmt.Errorf("invalid token: invalid length")
		}
		pk, ok := pubKey.(ed448.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid token: invalid public key type: required ed448.PublicKey")
		}
		if !ed448.Verify(pk, decoded[9:9+dataLength], decoded[9+dataLength:], "github.com/DeltaLaboratory/mwt") {
			return nil, fmt.Errorf("invalid token: invalid signature")
		}
	default:
		return nil, fmt.Errorf("invalid token: invalid signature type: %d", decoded[0])
	}

	result := new(T)
	if err := msgpack.Unmarshal(decoded[9:9+dataLength], result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return result, nil
}
