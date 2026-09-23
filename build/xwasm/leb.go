package xwasm

import "io"

// DecodeULEB128 decodes an unsigned LEB128 value of at most bits bits (1 to
// 64), returning the value and the number of bytes consumed.
//
// WebAssembly is stricter than DWARF about LEB128: an encoding may use at most
// ceil(bits/7) bytes, and the bits of the last byte past the type's width must
// be zero. A violation is an error, not a truncation; in a module it means the
// decoder has lost its place.
func DecodeULEB128(b []byte, bits int) (v uint64, n int, err error) {
	maxBytes := (bits + 6) / 7
	var shift uint
	for n < len(b) {
		c := b[n]
		n++
		if n == maxBytes {
			if rem := bits - int(shift); rem < 7 && c>>rem != 0 {
				return 0, n, errLEBOverflow // Also catches a continuation bit.
			}
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, n, nil
		}
		if n == maxBytes {
			return 0, n, errLEBTooLong
		}
		shift += 7
	}
	return 0, n, io.ErrUnexpectedEOF
}

// DecodeSLEB128 decodes a signed LEB128 value of at most bits bits (1 to 64)
// under the same rules as [DecodeULEB128]: at most ceil(bits/7) bytes, and the
// unused bits of the last byte must repeat the sign bit.
func DecodeSLEB128(b []byte, bits int) (v int64, n int, err error) {
	maxBytes := (bits + 6) / 7
	var shift uint
	for n < len(b) {
		c := b[n]
		n++
		if n == maxBytes {
			if c&0x80 != 0 {
				return 0, n, errLEBTooLong
			}
			// The payload's sign bit and every payload bit above the type's
			// width must agree: all clear or all set.
			rem := bits - int(shift)
			top := (c & 0x7f) >> (rem - 1)
			if top != 0 && top != 0x7f>>(rem-1) {
				return 0, n, errLEBOverflow
			}
		}
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, n, nil
		}
		if n == maxBytes {
			return 0, n, errLEBTooLong
		}
	}
	return 0, n, io.ErrUnexpectedEOF
}
