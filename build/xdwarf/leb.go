package xdwarf

import "io"

// DecodeULEB128 decodes an unsigned little-endian base 128 value, returning the
// value and the number of bytes consumed.
//
// A value wider than 64 bits is rejected rather than silently truncated: DWARF
// producers do not emit them, so one appearing means the stream is misaligned.
func DecodeULEB128(b []byte) (v uint64, n int, err error) {
	var shift uint
	for n < len(b) {
		c := b[n]
		n++
		if shift >= 64 {
			if c&0x7f != 0 {
				return 0, n, errLEBOverflow
			}
		} else {
			v |= uint64(c&0x7f) << shift
		}
		if c&0x80 == 0 {
			return v, n, nil
		}
		shift += 7
	}
	return 0, n, io.ErrUnexpectedEOF
}

// DecodeSLEB128 decodes a signed little-endian base 128 value.
func DecodeSLEB128(b []byte) (v int64, n int, err error) {
	var shift uint
	var c byte
	for n < len(b) {
		c = b[n]
		n++
		if shift < 64 {
			v |= int64(c&0x7f) << shift
		}
		shift += 7
		if c&0x80 == 0 {
			// Sign-extend from the final payload bit.
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, n, nil
		}
	}
	return 0, n, io.ErrUnexpectedEOF
}
