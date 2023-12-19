//go:build go1.21
// +build go1.21

package pkcs7

import (
	_ "unsafe"
)

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
	buf := makeNoZero(n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}

//go:linkname makeNoZero internal/bytealg.MakeNoZero
func makeNoZero(n int) []byte
