//go:build go1.21
// +build go1.21

package internal

import (
	_ "unsafe"
)

//go:linkname Alloc internal/bytealg.MakeNoZero
func Alloc(n int) []byte
