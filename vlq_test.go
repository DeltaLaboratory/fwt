package fwt

import (
	"bytes"
	"flag"
	"testing"
)

var flagUint32Range = flag.Bool("uint32-range", false, "Run the full uint32 range test")

func TestVLQEncodeDecode(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		wantLen  int
		wantErr  bool
		maxBytes int // maximum bytes needed for encoding
	}{
		{"zero", 0, 1, false, 1},
		{"one-byte-min", 1, 1, false, 1},
		{"one-byte-max", 127, 1, false, 1},
		{"two-bytes-min", 128, 2, false, 2},
		{"two-bytes-mid", 255, 2, false, 2},
		{"two-bytes-max", 16384, 2, false, 2},
		{"large-value", 1234567890, 5, false, 5},
		{"max-uint32", uint64(^uint32(0)), 5, false, 5},
		{"max-uint64", ^uint64(0), 10, false, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test encoding
			buf := make([]byte, tt.maxBytes)
			gotLen, err := encodeVLQ(buf, tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("encodeVLQ() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && gotLen != tt.wantLen {
				t.Errorf("encodeVLQ() length = %v, want %v", gotLen, tt.wantLen)
			}

			// Test decoding
			if !tt.wantErr {
				gotValue, gotBytesRead, err := decodeVLQ(buf[:gotLen])
				if err != nil {
					t.Errorf("decodeVLQ() unexpected error = %v", err)
					return
				}
				if gotValue != tt.value {
					t.Errorf("decodeVLQ() value = %v, want %v", gotValue, tt.value)
				}
				if gotBytesRead != tt.wantLen {
					t.Errorf("decodeVLQ() bytesRead = %v, want %v", gotBytesRead, tt.wantLen)
				}
			}
		})
	}
}

func TestVLQEncodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		value   uint64
		bufSize int
	}{
		{"buffer-too-small-one-byte", 127, 0},
		{"buffer-too-small-two-bytes", 128, 1},
		{"buffer-too-small-large-value", 1234567890, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufSize)
			_, err := encodeVLQ(buf, tt.value)
			if err == nil {
				t.Error("encodeVLQ() expected error for small buffer")
			}
		})
	}
}

func TestVLQDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty-input", []byte{}},
		{"incomplete-sequence", []byte{0x80}},
		{"too-long-sequence", bytes.Repeat([]byte{0x80}, 10)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeVLQ(tt.data)
			if err == nil {
				t.Error("decodeVLQ() expected error")
			}
		})
	}
}

func TestVLQUint32RangeRoundTrip(t *testing.T) {
	if !*flagUint32Range {
		t.Skip("Skipping full uint32 range test. Use -uint32-range flag to enable")
	}

	// Note: this test requires adjusting test timeout to run the full range
	// until https://github.com/golang/go/issues/48157 implemented

	// Test the full range of uint32 values
	for i := uint32(0); i <= ^uint32(0); i++ {
		buf := make([]byte, 5)
		n, err := encodeVLQ(buf, uint64(i))
		if err != nil {
			t.Errorf("encodeVLQ() error = %v", err)
			continue
		}

		decoded, bytesRead, err := decodeVLQ(buf[:n])
		if err != nil {
			t.Errorf("decodeVLQ() error = %v", err)
			continue
		}

		if uint32(decoded) != i {
			t.Errorf("Round trip failed: got %d, want %d", decoded, i)
		}
		if bytesRead != n {
			t.Errorf("Bytes read mismatch: got %d, want %d", bytesRead, n)
		}
	}
}

// FuzzVLQRoundTrip tests that encoding and then decoding a value produces the original value
func FuzzVLQRoundTrip(f *testing.F) {
	// Add some seed values
	seeds := []uint64{0, 1, 127, 128, 16383, 16384, 1234567890}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, original uint64) {
		// Encode
		buf := make([]byte, 9) // Maximum possible size for uint64
		n, err := encodeVLQ(buf, original)
		if err != nil {
			t.Skip() // Skip if we can't encode (e.g., too large values)
		}

		// Decode
		decoded, bytesRead, err := decodeVLQ(buf[:n])
		if err != nil {
			t.Errorf("decodeVLQ() error = %v", err)
			return
		}

		// Verify
		if decoded != original {
			t.Errorf("Round trip failed: got %d, want %d", decoded, original)
		}
		if bytesRead != n {
			t.Errorf("Bytes read mismatch: got %d, want %d", bytesRead, n)
		}
	})
}

// FuzzVLQDecode tests the decoder with random byte sequences
func FuzzVLQDecode(f *testing.F) {
	// Add some seed values
	seeds := [][]byte{
		{0x00},
		{0x7f},
		{0x80, 0x01},
		{0xff, 0x7f},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		value, bytesRead, err := decodeVLQ(data)
		if err != nil {
			// Ensure we don't read past the input length
			if bytesRead > len(data) {
				t.Errorf("Read past end of input: bytesRead=%d, len(data)=%d", bytesRead, len(data))
			}
			return
		}

		// If decode succeeded, verify constraints
		if bytesRead == 0 {
			t.Error("Successful decode reported 0 bytes read")
		}
		if bytesRead > 9 {
			t.Error("Decoded more than 9 bytes")
		}

		// Verify the decoded value can be re-encoded
		buf := make([]byte, 9)
		encLen, encErr := encodeVLQ(buf, value)
		if encErr != nil {
			t.Errorf("Failed to re-encode decoded value %d: %v", value, encErr)
		}

		// Verify the re-encoded value decodes to the same value
		reDecoded, reDecodedBytes, reDecodeErr := decodeVLQ(buf[:encLen])
		if reDecodeErr != nil {
			t.Errorf("Failed to re-decode value: %v", reDecodeErr)
		}
		if reDecoded != value {
			t.Errorf("Re-decoded value mismatch: got %d, want %d", reDecoded, value)
		}
		if reDecodedBytes != encLen {
			t.Errorf("Re-decoded bytes mismatch: got %d, want %d", reDecodedBytes, encLen)
		}
	})
}
