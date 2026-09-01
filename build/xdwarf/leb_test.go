package xdwarf

import (
	"math"
	"testing"
)

func TestDecodeULEB128(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x01}, 1, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xe5, 0x8e, 0x26}, 624485, 3},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0x0f}, math.MaxUint32, 5},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, math.MaxUint64, 10},
		// Trailing bytes must not be consumed.
		{[]byte{0x01, 0xff, 0xff}, 1, 1},
	} {
		got, n, err := DecodeULEB128(tc.b)
		if err != nil {
			t.Errorf("DecodeULEB128(%x): %s", tc.b, err)
			continue
		}
		if got != tc.want || n != tc.n {
			t.Errorf("DecodeULEB128(%x)=(%d,%d) want (%d,%d)", tc.b, got, n, tc.want, tc.n)
		}
	}
}

func TestDecodeSLEB128(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		want int64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x01}, 1, 1},
		{[]byte{0x7f}, -1, 1},
		{[]byte{0x3f}, 63, 1},
		{[]byte{0x40}, -64, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0x80, 0x7f}, -128, 2},
		{[]byte{0xc0, 0xbb, 0x78}, -123456, 3},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0x07}, math.MaxInt32, 5},
	} {
		got, n, err := DecodeSLEB128(tc.b)
		if err != nil {
			t.Errorf("DecodeSLEB128(%x): %s", tc.b, err)
			continue
		}
		if got != tc.want || n != tc.n {
			t.Errorf("DecodeSLEB128(%x)=(%d,%d) want (%d,%d)", tc.b, got, n, tc.want, tc.n)
		}
	}
}

// TestDecodeLEBTruncated pins that a value running off the end of the buffer is
// an error rather than a silently short read: a DWARF stream that ends mid-value
// is corrupt, and continuing would desynchronize every following opcode.
func TestDecodeLEBTruncated(t *testing.T) {
	truncated := [][]byte{
		{},
		{0x80},
		{0x80, 0x80},
		{0xff, 0xff, 0xff},
	}
	for _, b := range truncated {
		if _, _, err := DecodeULEB128(b); err == nil {
			t.Errorf("DecodeULEB128(%x) accepted a truncated value", b)
		}
		if _, _, err := DecodeSLEB128(b); err == nil {
			t.Errorf("DecodeSLEB128(%x) accepted a truncated value", b)
		}
	}
}

// TestDecodeULEB128Overflow pins that a value too wide for 64 bits is rejected
// rather than wrapping.
func TestDecodeULEB128Overflow(t *testing.T) {
	// Eleven continuation bytes carrying payload past bit 64.
	b := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
	if _, _, err := DecodeULEB128(b); err == nil {
		t.Error("an over-wide ULEB128 value was accepted")
	}
	// Padding a representable value with redundant zero-payload bytes is legal.
	ok := []byte{0x01, 0x80, 0x80}
	copy(ok, []byte{0x81, 0x80, 0x00})
	if v, _, err := DecodeULEB128(ok); err != nil || v != 1 {
		t.Errorf("redundant padding rejected: v=%d err=%v", v, err)
	}
}
