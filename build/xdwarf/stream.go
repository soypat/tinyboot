package xdwarf

import (
	"encoding/binary"
	"io"

	"github.com/soypat/lexorg"
)

// streamCursor is [cursor] for a span too large to hold resident: the opcode
// stream, which is consumed once, forward, and is the bulk of .debug_line.
//
// It is a separate type rather than an interface behind [cursor] because the
// row loop reads a byte at a time, and dynamic dispatch there would cost more
// than the windowing saves. Its surface is correspondingly narrow -- an opcode
// stream holds no strings -- and, like [cursor], it records the first error it
// hits and then reports zero values.
type streamCursor struct {
	wr  lexorg.WindowReader
	bo  binary.ByteOrder
	end int64 // Absolute offset one past the last byte of the unit.
	err error
}

func (c *streamCursor) config(r io.ReaderAt, buf []byte, start, end int64, bo binary.ByteOrder) {
	c.wr.Reset(r, buf, start)
	c.bo, c.end, c.err = bo, end, nil
}

// pos reports the absolute offset within the section the next read starts at.
func (c *streamCursor) pos() int64 { return c.wr.Offset() }

// seek moves the cursor, which costs no read when the target is already
// resident -- the case that matters, since seeking is how an opcode whose body
// this package ignores gets skipped.
func (c *streamCursor) seek(off int64) {
	if c.err != nil {
		return
	}
	c.wr.Reset(c.wr.ReaderAt(), nil, off)
}

func (c *streamCursor) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

// read returns the next n bytes in place, refusing to run past the end of the
// unit. n is never more than 8, well under any sane fill size.
func (c *streamCursor) read(n int) []byte {
	if c.err != nil {
		return nil
	}
	if c.pos()+int64(n) > c.end {
		c.fail(makeFormatErr(uint64(c.pos()), "read past end of unit", n))
		return nil
	}
	b, err := c.wr.ReadView(n)
	if err != nil {
		c.fail(err)
		return nil
	}
	return b
}

func (c *streamCursor) u8() uint8 {
	if c.err != nil {
		return 0
	}
	if c.pos() >= c.end {
		c.fail(makeFormatErr(uint64(c.pos()), "read past end of unit", 1))
		return 0
	}
	b, err := c.wr.ReadByte()
	if err != nil {
		c.fail(err)
		return 0
	}
	return b
}

func (c *streamCursor) u16() uint16 {
	b := c.read(2)
	if b == nil {
		return 0
	}
	return c.bo.Uint16(b)
}

func (c *streamCursor) u32() uint32 {
	b := c.read(4)
	if b == nil {
		return 0
	}
	return c.bo.Uint32(b)
}

func (c *streamCursor) u64() uint64 {
	b := c.read(8)
	if b == nil {
		return 0
	}
	return c.bo.Uint64(b)
}

// uleb mirrors [DecodeULEB128] over the stream, rejecting a value wider than 64
// bits rather than truncating it: DWARF producers do not emit them, so one
// appearing means the stream is misaligned.
func (c *streamCursor) uleb() uint64 {
	var v uint64
	var shift uint
	for {
		b := c.u8()
		if c.err != nil {
			return 0
		}
		if shift >= 64 {
			if b&0x7f != 0 {
				c.fail(errLEBOverflow)
				return 0
			}
		} else {
			v |= uint64(b&0x7f) << shift
		}
		if b&0x80 == 0 {
			return v
		}
		shift += 7
	}
}

// sleb mirrors [DecodeSLEB128] over the stream.
func (c *streamCursor) sleb() int64 {
	var v int64
	var shift uint
	for {
		b := c.u8()
		if c.err != nil {
			return 0
		}
		if shift < 64 {
			v |= int64(b&0x7f) << shift
		}
		shift += 7
		if b&0x80 == 0 {
			// Sign-extend from the final payload bit.
			if shift < 64 && b&0x40 != 0 {
				v |= -1 << shift
			}
			return v
		}
	}
}
