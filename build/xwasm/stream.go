package xwasm

import (
	"io"

	"github.com/soypat/lexorg"
	"github.com/soypat/tinyboot/build"
)

// cursor reads a section's contents forward through a caller-owned window,
// refusing to run past the section's end. It records the first error it hits
// and then reports zero values, so a decoder can read a whole structure and
// check for failure once at the end.
//
// It is xdwarf's streamCursor adapted to WebAssembly's width-bounded LEB128.
type cursor struct {
	wr  lexorg.WindowReader
	end int64 // Absolute offset one past the last byte the cursor may read.
	err error
}

// reset binds the cursor to [start, end) of r. It always discards what the
// window holds: the same reader and buffer may now describe different bytes,
// since a File can be re-read from a reader whose contents changed, and a
// caller may have lent the buffer to another reader in between.
func (c *cursor) reset(r io.ReaderAt, buf []byte, start, end int64) {
	c.wr.Reset(r, buf, start)
	c.wr.Drop()
	c.end, c.err = end, nil
}

// pos reports the absolute offset the next read starts at.
func (c *cursor) pos() int64 { return c.wr.Offset() }

func (c *cursor) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

// seek moves the cursor to off, which costs no read when off is resident.
func (c *cursor) seek(off int64) {
	if c.err != nil {
		return
	}
	if off > c.end || off < 0 {
		c.fail(build.ErrPastSectionEnd)
		return
	}
	c.wr.Reset(c.wr.ReaderAt(), nil, off)
}

// skip advances the cursor by n bytes without reading them.
func (c *cursor) skip(n uint64) {
	if c.err != nil {
		return
	}
	if n > uint64(c.end-c.pos()) {
		c.fail(build.ErrPastSectionEnd)
		return
	}
	c.seek(c.pos() + int64(n))
}

func (c *cursor) u8() uint8 {
	if c.err != nil {
		return 0
	}
	if c.pos() >= c.end {
		c.fail(build.ErrPastSectionEnd)
		return 0
	}
	b, err := c.wr.ReadByte()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		c.fail(err)
		return 0
	}
	return b
}

// uleb reads an unsigned LEB128 of at most bits bits, under the rules of
// [DecodeULEB128].
func (c *cursor) uleb(bits int) uint64 {
	maxBytes := (bits + 6) / 7
	var v uint64
	var shift uint
	for n := 1; ; n++ {
		b := c.u8()
		if c.err != nil {
			return 0
		}
		if n == maxBytes {
			if b&0x80 != 0 {
				c.fail(build.ErrLEBTooLong)
				return 0
			}
			if rem := bits - int(shift); rem < 7 && b>>rem != 0 {
				c.fail(build.ErrLEBOverflow)
				return 0
			}
		}
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v
		}
		shift += 7
	}
}

func (c *cursor) u32() uint32 { return uint32(c.uleb(32)) }

// sleb reads a signed LEB128 of at most bits bits, under the rules of
// [DecodeSLEB128].
func (c *cursor) sleb(bits int) int64 {
	maxBytes := (bits + 6) / 7
	var v int64
	var shift uint
	for n := 1; ; n++ {
		b := c.u8()
		if c.err != nil {
			return 0
		}
		if n == maxBytes {
			if b&0x80 != 0 {
				c.fail(build.ErrLEBTooLong)
				return 0
			}
			rem := bits - int(shift)
			if top := (b & 0x7f) >> (rem - 1); top != 0 && top != 0x7f>>(rem-1) {
				c.fail(build.ErrLEBOverflow)
				return 0
			}
		}
		v |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && b&0x40 != 0 {
				v |= -1 << shift
			}
			return v
		}
	}
}

// vecLen reads a vector's element count and rejects one that cannot fit in the
// rest of the section when every element takes at least minElem bytes. Counts
// come straight from the file, so this is what stops a loop over a forged count
// from spinning for billions of iterations before it notices the section ended.
func (c *cursor) vecLen(minElem uint64) uint32 {
	n := c.u32()
	if c.err == nil && uint64(n)*minElem > uint64(c.end-c.pos()) {
		c.fail(build.ErrCountExceedsSection)
		return 0
	}
	return n
}

// skipName skips a length-prefixed byte string.
func (c *cursor) skipName() {
	c.skip(uint64(c.u32()))
}

// limits skips a table or memory limits structure. The flags byte admits the
// shared-memory and memory64 proposals: bit 0 has-max, bit 1 shared, bit 2
// 64-bit bounds.
func (c *cursor) limits() {
	flags := c.u8()
	if c.err == nil && flags > 7 {
		c.fail(build.ErrBadLimits)
		return
	}
	bits := 32
	if flags&4 != 0 {
		bits = 64
	}
	c.uleb(bits)
	if flags&1 != 0 {
		c.uleb(bits)
	}
}

// valType skips a value or reference type. The typed function references and
// GC proposals prefix a heap type with 0x63 (nullable) or 0x64 (non-null);
// every other type is a single byte.
func (c *cursor) valType() {
	switch c.u8() {
	case 0x63, 0x64:
		c.sleb(33)
	}
}
