package pkcs7

import (
	"errors"

	"github.com/DeltaLaboratory/fwt/v2/internal/memory"
)

// PKCS7 errors.
var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blockSize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

// Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func Pad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blockSize - (len(b) % blockSize)
	return append(b, repeatByte(byte(n), n)...), nil
}

// Unpad validates and unpads data from the given bytes slice.
// The returned value will be one to n bytes smaller depending on the
// amount of padding, where n is the block size.
func Unpad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blockSize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

func repeatByte(b byte, n int) []byte {
	if n < 0 {
		panic("repeatByte: negative count")
	}
	if n == 0 {
		return nil
	}
	if n == 1 {
		return []byte{b}
	}
	buf := memory.Alloc(n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
