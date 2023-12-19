//go:build !go1.21
// +build !go1.21

package pkcs7

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
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
