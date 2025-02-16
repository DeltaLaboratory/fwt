//go:build go1.21
// +build go1.21

package memory

import (
	_ "unsafe"
)

//go:linkname Alloc internal/bytealg.MakeNoZero
func Alloc(n int) []byte
