package fwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/DeltaLaboratory/fwt/internal"
	"github.com/DeltaLaboratory/fwt/internal/pkcs7"
)

type EncryptorFactory func() (EncryptorFunc, error)
type EncryptorFunc func([]byte) ([]byte, error)

type DecrypterFactory func() (DecrypterFunc, error)
type DecrypterFunc func([]byte) ([]byte, error)

// NewXChaCha20PolyEncryptor creates a new encryptor using XChaCha20-Poly1305.
func NewXChaCha20PolyEncryptor(key []byte, randPool ...io.Reader) EncryptorFactory {
	return func() (EncryptorFunc, error) {
		var randReader io.Reader
		if len(randPool) > 0 {
			randReader = randPool[0]
		} else {
			randReader = rand.Reader
		}

		AEAD, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			nonce := internal.Alloc(chacha20poly1305.NonceSizeX + len(data) + chacha20poly1305.Overhead)
			// Set length of allocated buffer to the length of the nonce
			nonce = nonce[:chacha20poly1305.NonceSizeX]

			if _, err := io.ReadFull(randReader, nonce); err != nil {
				return nil, fmt.Errorf("failed to generate nonce: %w", err)
			}

			return AEAD.Seal(nonce, nonce, data, nil), nil
		}, nil
	}
}

// NewXChaCha20PolyDecrypter creates a new decrypter using XChaCha20-Poly1305.
func NewXChaCha20PolyDecrypter(key []byte) DecrypterFactory {
	return func() (DecrypterFunc, error) {
		AEAD, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			if len(data) < chacha20poly1305.NonceSizeX {
				return nil, fmt.Errorf("invalid data")
			}
			return AEAD.Open(nil, data[:chacha20poly1305.NonceSizeX], data[chacha20poly1305.NonceSizeX:], nil)
		}, nil
	}
}

// NewAESECBEncryptor creates a new encryptor using AES-ECB.
// Disclaimer: ECB is not secure, it must not be used in production.
// Please use AES-CBC or AES-GCM instead.
// See https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB).
func NewAESECBEncryptor(key []byte) EncryptorFactory {
	return func() (EncryptorFunc, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			padded, err := pkcs7.Pad(data, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to pad data: %w", err)
			}
			cipherText := internal.Alloc(len(padded))

			for bs, be := 0, block.BlockSize(); bs < len(data); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
				block.Encrypt(cipherText[bs:be], padded[bs:be])
			}

			return cipherText, nil
		}, nil
	}

}

// NewAESECBDecrypter creates a new decrypter using AES-ECB.
// Disclaimer: ECB is not secure, it must not be used in production.
// Please use AES-CBC or AES-GCM instead.
// See https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB).
func NewAESECBDecrypter(key []byte) DecrypterFactory {
	return func() (DecrypterFunc, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			if len(data)%aes.BlockSize != 0 {
				return nil, fmt.Errorf("invalid data")
			}
			plainText := internal.Alloc(len(data))

			for bs, be := 0, aes.BlockSize; bs < len(data); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
				block.Decrypt(plainText[bs:be], data[bs:be])
			}
			plainText, err = pkcs7.Unpad(plainText, 16)

			if err != nil {
				return nil, fmt.Errorf("failed to unpad data: %w", err)
			}

			return plainText, nil
		}, nil
	}

}

// NewAESCBCEncryptor creates a new encryptor using AES-CBC.
func NewAESCBCEncryptor(key []byte, randPool ...io.Reader) EncryptorFactory {
	return func() (EncryptorFunc, error) {
		var randReader io.Reader
		if len(randPool) > 0 {
			randReader = randPool[0]
		} else {
			randReader = rand.Reader
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			padded, err := pkcs7.Pad(data, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to pad data: %w", err)
			}
			cipherText := internal.Alloc(16 + len(padded))

			if _, err := io.ReadFull(randReader, cipherText[:16]); err != nil {
				return nil, fmt.Errorf("failed to generate nonce: %w", err)
			}

			encryptor := cipher.NewCBCEncrypter(block, cipherText[:16])
			encryptor.CryptBlocks(cipherText[16:], padded)
			return cipherText, nil
		}, nil
	}
}

// NewAESCBCDecrypter creates a new decrypter using AES-CBC.
func NewAESCBCDecrypter(key []byte) DecrypterFactory {
	return func() (DecrypterFunc, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			if len(data) < 16 {
				return nil, fmt.Errorf("invalid data")
			}

			decrypter := cipher.NewCBCDecrypter(block, data[:16])
			decrypter.CryptBlocks(data[16:], data[16:])
			data, err = pkcs7.Unpad(data[16:], aes.BlockSize)
			if err != nil {
				return nil, fmt.Errorf("failed to unpad data: %w", err)
			}

			return data, nil
		}, nil
	}
}

// NewAESCTREncryptor creates a new encryptor using AES-CTR.
func NewAESCTREncryptor(key []byte, randPool ...io.Reader) EncryptorFactory {
	return func() (EncryptorFunc, error) {
		var randReader io.Reader
		if len(randPool) > 0 {
			randReader = randPool[0]
		} else {
			randReader = rand.Reader
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			cipherText := internal.Alloc(16 + len(data))
			if _, err := io.ReadFull(randReader, cipherText[:16]); err != nil {
				return nil, fmt.Errorf("failed to generate nonce: %w", err)
			}
			encryptor := cipher.NewCTR(block, cipherText[:16])
			encryptor.XORKeyStream(cipherText[16:], data)
			return cipherText, nil
		}, nil
	}
}

// NewAESCTRDecrypter creates a new decrypter using AES-CTR.
func NewAESCTRDecrypter(key []byte) DecrypterFactory {
	return func() (DecrypterFunc, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			if len(data) < 16 {
				return nil, fmt.Errorf("invalid data")
			}
			decrypter := cipher.NewCTR(block, data[:16])
			decrypter.XORKeyStream(data[16:], data[16:])
			return data[16:], nil
		}, nil
	}
}

// NewAESGCMEncryptor creates a new encryptor using AES-GCM.
func NewAESGCMEncryptor(key []byte, randPool ...io.Reader) EncryptorFactory {
	return func() (EncryptorFunc, error) {
		var randReader io.Reader
		if len(randPool) > 0 {
			randReader = randPool[0]
		} else {
			randReader = rand.Reader
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}

		AEAD, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			nonce := internal.Alloc(12)
			if _, err := io.ReadFull(randReader, nonce); err != nil {
				return nil, fmt.Errorf("failed to generate nonce: %w", err)
			}
			return AEAD.Seal(nonce, nonce, data, nil), nil
		}, nil
	}
}

// NewAESGCMDecrypter creates a new decrypter using AES-GCM.
func NewAESGCMDecrypter(key []byte) DecrypterFactory {
	return func() (DecrypterFunc, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		AEAD, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		return func(data []byte) ([]byte, error) {
			if len(data) < 12 {
				return nil, fmt.Errorf("invalid data")
			}
			return AEAD.Open(nil, data[:12], data[12:], nil)
		}, nil
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
			sender, err = suite.NewSender(key, []byte{})
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
			receiver, err = suite.NewReceiver(key, []byte{})
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
