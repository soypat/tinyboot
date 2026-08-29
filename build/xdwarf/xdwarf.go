// Package xdwarf decodes the subset of DWARF needed to attribute machine code
// to source, in the allocation-conscious style of [xelf].
//
// It is deliberately not a mirror of the standard library's debug/dwarf. That
// package materializes every DIE as an *Entry holding a []Field of boxed any
// values, which costs an allocation per attribute; walking a firmware image's
// .debug_info to extract four attributes from two tag types pays that cost tens
// of thousands of times. xdwarf instead streams: a caller supplies a callback
// and receives values decoded in place, and everything of unbounded length goes
// through an Append method onto a caller-owned buffer.
//
// The scope is line-number information: enough to answer "which source file and
// line do these bytes come from". Type information, call frame information and
// location lists are out of scope.
//
// [xelf]: github.com/soypat/tinyboot/build/xelf
package xdwarf

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errLEBOverflow    = errors.New("LEB128 value overflows 64 bits")
	errShortSection   = errors.New("truncated DWARF section")
	errBadVersion     = errors.New("unsupported DWARF version")
	errBadForm        = errors.New("unsupported DWARF form")
	errNoLineSection  = errors.New("no .debug_line section")
	errBadFileIndex   = errors.New("file index out of range")
	errBadOpcodeBase  = errors.New("invalid opcode_base in line program header")
	errUnitOutOfRange = errors.New("unit offset out of range")
)

// makeFormatErr mirrors xelf.makeFormatErr: it reports the offset at which a
// malformed structure was found, which is what makes a corrupt DWARF section
// diagnosable at all.
func makeFormatErr(off uint64, msg string, val any) error {
	if str, ok := val.(fmt.Stringer); ok {
		val = str.String()
	}
	return fmt.Errorf("DWARF format error: %s @ off=%d: %v", msg, off, val)
}

// Sections holds the DWARF section payloads a reader needs, already extracted
// from the container and relocated if the object required it. Callers fill in
// what they have; an operation that needs a section absent here fails rather
// than guessing.
//
// Obtain the bytes with xelf:
//
//	sec, _ := f.SectionByName(".debug_line")
//	s.Line, _ = sec.AppendData(nil)
type Sections struct {
	Line      []byte // .debug_line
	LineStr   []byte // .debug_line_str, DWARF 5 only.
	Str       []byte // .debug_str
	ByteOrder binary.ByteOrder
}

func (s *Sections) byteOrder() binary.ByteOrder {
	if s.ByteOrder == nil {
		return binary.LittleEndian
	}
	return s.ByteOrder
}

// strSection identifies which section a string lives in. Names in a line
// program header may point into three different places depending on form, and
// resolving them eagerly would mean copying every string in the table.
type strSection uint8

const (
	strInline   strSection = iota // Bytes are in .debug_line itself.
	strDebugStr                   // Offset into .debug_str.
	strLineStr                    // Offset into .debug_line_str.
)

// cursor is a bounds-checked read head over a byte slice. It records the first
// error it hits and then reports zero values, so a decoder can read a whole
// structure and check for failure once at the end rather than after every field.
type cursor struct {
	b    []byte
	off  int
	bo   binary.ByteOrder
	err  error
	base int // Offset of b within its section, for error reporting.
}

func (c *cursor) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

func (c *cursor) remaining() int { return len(c.b) - c.off }

func (c *cursor) bytes(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || c.remaining() < n {
		c.fail(makeFormatErr(uint64(c.base+c.off), "short read", n))
		return nil
	}
	out := c.b[c.off : c.off+n]
	c.off += n
	return out
}

func (c *cursor) u8() uint8 {
	b := c.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (c *cursor) u16() uint16 {
	b := c.bytes(2)
	if b == nil {
		return 0
	}
	return c.bo.Uint16(b)
}

func (c *cursor) u32() uint32 {
	b := c.bytes(4)
	if b == nil {
		return 0
	}
	return c.bo.Uint32(b)
}

func (c *cursor) u64() uint64 {
	b := c.bytes(8)
	if b == nil {
		return 0
	}
	return c.bo.Uint64(b)
}

func (c *cursor) uleb() uint64 {
	if c.err != nil {
		return 0
	}
	v, n, err := DecodeULEB128(c.b[c.off:])
	if err != nil {
		c.fail(err)
		return 0
	}
	c.off += n
	return v
}

func (c *cursor) sleb() int64 {
	if c.err != nil {
		return 0
	}
	v, n, err := DecodeSLEB128(c.b[c.off:])
	if err != nil {
		c.fail(err)
		return 0
	}
	c.off += n
	return v
}

// cstr returns the offset and length of a NUL-terminated string at the cursor,
// consuming it along with its terminator. The bytes are not copied.
func (c *cursor) cstr() (off, length int) {
	if c.err != nil {
		return 0, 0
	}
	start := c.off
	for c.off < len(c.b) {
		if c.b[c.off] == 0 {
			c.off++
			return start, c.off - 1 - start
		}
		c.off++
	}
	c.fail(makeFormatErr(uint64(c.base+start), "unterminated string", nil))
	return 0, 0
}

// offset reads a section offset, 4 bytes in the 32-bit DWARF format and 8 in
// the 64-bit one.
func (c *cursor) offset(dwarf64 bool) uint64 {
	if dwarf64 {
		return c.u64()
	}
	return uint64(c.u32())
}
