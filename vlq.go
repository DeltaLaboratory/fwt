package fwt

import (
	"errors"
)

// See https://github.com/git/git/blob/master/varint.c to original Git's VLQ implementation

var (
	ErrEmptyBuffer      = errors.New("empty buffer")
	ErrIncompleteNumber = errors.New("incomplete VLQ number")
	ErrBufferTooSmall   = errors.New("buffer too small")
	ErrValueTooLarge    = errors.New("value too large to encode")
)

// decodeVLQ decodes a variable-length quantity from the given buffer.
// It returns the decoded value, the number of bytes read, and an error if any.
func decodeVLQ(buffer []byte) (uint64, int, error) {
	if len(buffer) == 0 {
		return 0, 0, ErrEmptyBuffer
	}

	var val uint64
	var bytesRead int

	// Read first byte
	c := buffer[bytesRead]
	bytesRead++
	val = uint64(c & 0x7F)

	// Continue reading while the continuation bit is set
	for c&0x80 != 0 {
		if bytesRead >= len(buffer) {
			return 0, bytesRead, ErrIncompleteNumber
		}

		val++

		// Check for overflow
		//if val == 0 || (val & ^uint64(0x7F)) != 0 {
		//	return 0, bytesRead, ErrOverflow
		//}

		c = buffer[bytesRead]
		bytesRead++
		val = (val << 7) + uint64(c&0x7F)
	}

	return val, bytesRead, nil
}

// encodeVLQ encodes a variable-length quantity to the given buffer.
// It returns the number of bytes written and an error if any.
func encodeVLQ(buffer []byte, value uint64) (int, error) {
	if len(buffer) == 0 {
		return 0, ErrBufferTooSmall
	}

	var varint [16]byte
	pos := len(varint) - 1

	// Encode the least significant 7 bits
	varint[pos] = byte(value & 0x7F)

	// Continue encoding while there are more bits
	// while (value >>= 7)
	//		varint[--pos] = 128 | (--value & 127);
	for value >>= 7; value > 0; value >>= 7 {
		pos--
		if pos < 0 {
			return 0, ErrValueTooLarge
		}
		value--

		varint[pos] = byte(0x80 | (value & 0x7F))
	}

	// Check if the target buffer is large enough
	bytesToWrite := len(varint) - pos
	if len(buffer) < bytesToWrite {
		return 0, ErrBufferTooSmall
	}

	// Copy the encoded bytes to the target buffer
	copy(buffer, varint[pos:])
	return bytesToWrite, nil
}
