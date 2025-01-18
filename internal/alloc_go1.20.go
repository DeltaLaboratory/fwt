//go:build !go1.21
// +build !go1.21

package internal

func Alloc(n int) []byte {
	return make([]byte, n)
}
