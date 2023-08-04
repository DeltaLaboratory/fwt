package fwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/DeltaLaboratory/fwt/internal/pkcs7"
)

func NewXChaCha20PolyEncryptor(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		AEAD, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		nonce := make([]byte, AEAD.NonceSize(), AEAD.NonceSize()+len(data)+AEAD.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		return AEAD.Seal(nonce, nonce, data, nil), nil
	}
}

func NewXChaCha20PolyDecrypter(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		AEAD, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		nonceSize := AEAD.NonceSize()
		if len(data) < nonceSize {
			return nil, fmt.Errorf("invalid data")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		return AEAD.Open(nil, nonce, ciphertext, nil)
	}
}

func NewAESCBCEncryptor(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		padded, err := pkcs7.Pad(data, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to pad data: %w", err)
		}
		cipherText := make([]byte, 16+len(padded))
		if _, err := rand.Read(cipherText[:16]); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		encryptor := cipher.NewCBCEncrypter(block, cipherText[:16])
		encryptor.CryptBlocks(cipherText[16:], padded)
		return cipherText, nil
	}
}

func NewAESCBCDecrypter(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		if len(data) < 16 {
			return nil, fmt.Errorf("invalid data")
		}
		decrypter := cipher.NewCBCDecrypter(block, data[:16])
		decrypter.CryptBlocks(data[16:], data[16:])
		data, err = pkcs7.Unpad(data[16:], 16)
		if err != nil {
			return nil, fmt.Errorf("failed to unpad data: %w", err)
		}
		return data, nil
	}
}
