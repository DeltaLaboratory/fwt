package fwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/DeltaLaboratory/fwt/internal/pkcs7"
)

// NewXChaCha20PolyEncryptor creates a new encryptor using XChaCha20-Poly1305.
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

// NewXChaCha20PolyDecrypter creates a new decrypter using XChaCha20-Poly1305.
func NewXChaCha20PolyDecrypter(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		AEAD, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		if len(data) < AEAD.NonceSize() {
			return nil, fmt.Errorf("invalid data")
		}
		return AEAD.Open(nil, data[:AEAD.NonceSize()], data[AEAD.NonceSize():], nil)
	}
}

// NewAESECBEncryptor creates a new encryptor using AES-ECB.
// Disclaimer: ECB is not secure, it must not be used in production.
// Please use AES-CBC or AES-GCM instead.
// See https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB).
func NewAESECBEncryptor(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		padded, err := pkcs7.Pad(data, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to pad data: %w", err)
		}
		cipherText := make([]byte, len(padded))
		for bs, be := 0, block.BlockSize(); bs < len(data); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
			block.Encrypt(cipherText[bs:be], padded[bs:be])
		}
		return cipherText, nil
	}
}

// NewAESECBDecrypter creates a new decrypter using AES-ECB.
// Disclaimer: ECB is not secure, it must not be used in production.
// Please use AES-CBC or AES-GCM instead.
// See https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB).
func NewAESECBDecrypter(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		if len(data)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("invalid data")
		}
		plainText := make([]byte, len(data))
		for bs, be := 0, block.BlockSize(); bs < len(data); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
			block.Decrypt(plainText[bs:be], data[bs:be])
		}
		plainText, err = pkcs7.Unpad(plainText, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to unpad data: %w", err)
		}
		return plainText, nil
	}
}

// NewAESCBCEncryptor creates a new encryptor using AES-CBC.
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

// NewAESCBCDecrypter creates a new decrypter using AES-CBC.
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

// NewAESCTREncryptor creates a new encryptor using AES-CTR.
func NewAESCTREncryptor(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		cipherText := make([]byte, 16+len(data))
		if _, err := rand.Read(cipherText[:16]); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		encryptor := cipher.NewCTR(block, cipherText[:16])
		encryptor.XORKeyStream(cipherText[16:], data)
		return cipherText, nil
	}
}

// NewAESCTRDecrypter creates a new decrypter using AES-CTR.
func NewAESCTRDecrypter(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		if len(data) < 16 {
			return nil, fmt.Errorf("invalid data")
		}
		decrypter := cipher.NewCTR(block, data[:16])
		decrypter.XORKeyStream(data[16:], data[16:])
		return data[16:], nil
	}
}

// NewAESGCMEncryptor creates a new encryptor using AES-GCM.
func NewAESGCMEncryptor(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		AEAD, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		return AEAD.Seal(nonce, nonce, data, nil), nil
	}
}

// NewAESGCMDecrypter creates a new decrypter using AES-GCM.
func NewAESGCMDecrypter(key []byte) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		if len(data) < 12 {
			return nil, fmt.Errorf("invalid data")
		}
		AEAD, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}
		return AEAD.Open(nil, data[:12], data[12:], nil)
	}
}

// NewHPKEEncryptor creates a new encryptor using HPKE.
// Experimental, not recommended for production use.
func NewHPKEEncryptor(key kem.PublicKey, suite hpke.Suite, info ...string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		var sender *hpke.Sender
		var err error
		if len(info) > 0 {
			sender, err = suite.NewSender(key, []byte(info[0]))
		} else {
			sender, err = suite.NewSender(key, []byte(defaultCtx))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create HPKE sender: %w", err)
		}
		enc, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to setup HPKE: %w", err)
		}
		encrypted, err := sealer.Seal(data, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}

		result := make([]byte, 8+len(enc)+len(encrypted))
		for i := 0; i < 8; i++ {
			result[i] = byte(len(enc) >> (8 * i))
		}
		copy(result[8:], enc)
		copy(result[8+len(enc):], encrypted)
		return result, nil
	}
}

// NewHPKEDecrypter creates a new decrypter using HPKE.
// Experimental, not recommended for production use.
func NewHPKEDecrypter(key kem.PrivateKey, suite hpke.Suite, info ...string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		encKeyLen := 0
		for i := 0; i < 8; i++ {
			encKeyLen |= int(data[i]) << (8 * i)
		}
		var receiver *hpke.Receiver
		var err error
		if len(info) > 0 {
			receiver, err = suite.NewReceiver(key, []byte(info[0]))
		} else {
			receiver, err = suite.NewReceiver(key, []byte(defaultCtx))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create HPKE receiver: %w", err)
		}
		opener, err := receiver.Setup(data[8 : 8+encKeyLen])
		if err != nil {
			return nil, fmt.Errorf("failed to setup HPKE: %w", err)
		}
		pt, err := opener.Open(data[8+encKeyLen:], nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return pt, nil
	}
}
