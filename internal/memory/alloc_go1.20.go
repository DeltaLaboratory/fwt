//go:build !go1.21
// +build !go1.21

package memory

func Alloc(n int) []byte {
	return make([]byte, n)
}
