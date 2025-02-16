package pkcs7

import (
	"bytes"
	"testing"
)

func TestPad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		want      []byte
		wantErr   error
	}{
		{
			name:      "normal padding - requiring full block",
			input:     []byte{1, 2, 3},
			blockSize: 8,
			want:      []byte{1, 2, 3, 5, 5, 5, 5, 5},
			wantErr:   nil,
		},
		{
			name:      "normal padding - partial block",
			input:     []byte{1, 2, 3, 4, 5},
			blockSize: 8,
			want:      []byte{1, 2, 3, 4, 5, 3, 3, 3},
			wantErr:   nil,
		},
		{
			name:      "single byte input",
			input:     []byte{1},
			blockSize: 4,
			want:      []byte{1, 3, 3, 3},
			wantErr:   nil,
		},
		{
			name:      "input size equals block size",
			input:     []byte{1, 2, 3, 4},
			blockSize: 4,
			want:      []byte{1, 2, 3, 4, 4, 4, 4, 4},
			wantErr:   nil,
		},
		{
			name:      "invalid block size",
			input:     []byte{1, 2, 3},
			blockSize: 0,
			want:      nil,
			wantErr:   ErrInvalidBlockSize,
		},
		{
			name:      "nil input",
			input:     nil,
			blockSize: 8,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Data,
		},
		{
			name:      "empty input",
			input:     []byte{},
			blockSize: 8,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Data,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Pad(tt.input, tt.blockSize)
			if err != tt.wantErr {
				t.Errorf("Pad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Pad() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnpad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		want      []byte
		wantErr   error
	}{
		{
			name:      "normal unpadding",
			input:     []byte{1, 2, 3, 5, 5, 5, 5, 5},
			blockSize: 8,
			want:      []byte{1, 2, 3},
			wantErr:   nil,
		},
		{
			name:      "unpad full padding block",
			input:     []byte{1, 2, 3, 4, 4, 4, 4, 4},
			blockSize: 4,
			want:      []byte{1, 2, 3, 4},
			wantErr:   nil,
		},
		{
			name:      "invalid block size",
			input:     []byte{1, 2, 3, 4},
			blockSize: 0,
			want:      nil,
			wantErr:   ErrInvalidBlockSize,
		},
		{
			name:      "nil input",
			input:     nil,
			blockSize: 8,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Data,
		},
		{
			name:      "empty input",
			input:     []byte{},
			blockSize: 8,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Data,
		},
		{
			name:      "invalid padding - wrong size",
			input:     []byte{1, 2, 3, 4, 5},
			blockSize: 4,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Padding,
		},
		{
			name:      "invalid padding - incorrect padding bytes",
			input:     []byte{1, 2, 3, 4, 5, 5, 5, 4},
			blockSize: 4,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Padding,
		},
		{
			name:      "invalid padding - zero padding value",
			input:     []byte{1, 2, 3, 0},
			blockSize: 4,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Padding,
		},
		{
			name:      "invalid padding - padding larger than input",
			input:     []byte{1, 2, 3, 5},
			blockSize: 4,
			want:      nil,
			wantErr:   ErrInvalidPKCS7Padding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Unpad(tt.input, tt.blockSize)
			if err != tt.wantErr {
				t.Errorf("Unpad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Unpad() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRepeatByte(t *testing.T) {
	tests := []struct {
		name  string
		b     byte
		count int
		want  []byte
	}{
		{
			name:  "zero count",
			b:     0x01,
			count: 0,
			want:  nil,
		},
		{
			name:  "single byte",
			b:     0x02,
			count: 1,
			want:  []byte{0x02},
		},
		{
			name:  "multiple bytes",
			b:     0x03,
			count: 4,
			want:  []byte{0x03, 0x03, 0x03, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := repeatByte(tt.b, tt.count)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("repeatByte() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
	}{
		{
			name:      "single byte",
			input:     []byte{1},
			blockSize: 8,
		},
		{
			name:      "multiple bytes",
			input:     []byte{1, 2, 3, 4, 5},
			blockSize: 8,
		},
		{
			name:      "block size aligned",
			input:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
			blockSize: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded, err := Pad(tt.input, tt.blockSize)
			if err != nil {
				t.Fatalf("Pad() error = %v", err)
			}

			unpadded, err := Unpad(padded, tt.blockSize)
			if err != nil {
				t.Fatalf("Unpad() error = %v", err)
			}

			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("Round trip failed: got %v, want %v", unpadded, tt.input)
			}
		})
	}
}

func TestRepeatBytePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("repeatByte() with negative count should panic")
		}
	}()

	repeatByte(0x01, -1)
}
