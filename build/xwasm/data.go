package xwasm

import "io"

import "github.com/soypat/tinyboot/build"

// DataSegment locates one segment of the Data section.
type DataSegment struct {
	// Index is the segment's index, which the name section keys names by.
	Index uint32
	// Offset is the position of the segment's first byte -- its flags --
	// measured from the start of the Data section's contents.
	Offset uint64
	// HeaderSize is the bytes the segment spends before its initializer: flags,
	// memory index, offset expression and byte count.
	HeaderSize uint32
	// Size is the length of the initializer bytes.
	Size uint64
	// Passive marks a segment copied into memory only by memory.init, which
	// has no address of its own.
	Passive bool
	// Addr is the linear-memory address an active segment is placed at, valid
	// when AddrKnown is set: the offset expression is a single constant. An
	// expression reading a global is only resolved at instantiation.
	Addr      uint64
	AddrKnown bool
}

// DataOffset returns the offset of the initializer bytes from the start of the
// Data section's contents.
func (s DataSegment) DataOffset() uint64 { return s.Offset + uint64(s.HeaderSize) }

// End returns the offset one past the segment's last byte, from the start of
// the Data section's contents.
func (s DataSegment) End() uint64 { return s.DataOffset() + s.Size }

// DataReader walks the segments of a module's Data section through a
// caller-owned buffer, without holding anything per segment. Segments come one
// at a time from [DataReader.Next], or all at once from [DataReader.Segments].
//
// A DataReader is reusable: [DataReader.Reset] points it at another module and
// keeps the buffer. The buffer belongs to the reader from Reset until the next
// Reset; lending it to another reader in between corrupts both walks.
type DataReader struct {
	c     cursor
	start int64
	count uint32
	next  uint32 // Index of the segment Next reads.
	done  bool
	err   error
}

// Reset points dr at f's Data section, reading through buf, and rewinds it to
// the first segment. As with [CodeReader], segment contents are skipped rather
// than read, so buf needs to hold only a few bytes. A module with no Data
// section yields no segments.
func (dr *DataReader) Reset(f *File, buf []byte) error {
	if len(buf) < maxSectionFrame {
		return io.ErrShortBuffer
	}
	*dr = DataReader{c: dr.c}
	sec, err := f.SectionByID(SecData)
	if err != nil {
		dr.c.reset(f.r, buf, 0, 0)
		dr.Rewind()
		return nil
	}
	sh := sec.SectionHeader()
	dr.start = int64(sh.Offset)
	dr.c.reset(f.r, buf, dr.start, int64(sh.End()))
	// The smallest segment is passive and empty: flags and a zero count.
	dr.count = dr.c.vecLen(2)
	if dr.c.err != nil {
		return dr.c.err
	}
	dr.Rewind()
	return nil
}

// NumSegments returns the number of segments in the Data section.
func (dr *DataReader) NumSegments() uint32 { return dr.count }

// Err returns why the walk stopped early, or nil if it ran to completion or the
// caller stopped it.
func (dr *DataReader) Err() error { return dr.err }

// Rewind positions dr before the first segment, to walk the segments anew.
func (dr *DataReader) Rewind() {
	c := &dr.c
	dr.err, dr.next, dr.done = nil, 0, dr.count == 0
	if dr.done {
		return
	}
	c.err = nil
	c.seek(dr.start)
	c.u32() // Count, validated by Reset.
}

// Next returns the next data segment in order of index. It reports false once
// the segments run out or the walk fails; [DataReader.Err] tells which.
func (dr *DataReader) Next() (DataSegment, bool) {
	if dr.done {
		return DataSegment{}, false
	}
	c := &dr.c
	if dr.next == dr.count {
		if c.err == nil && c.pos() != c.end {
			c.fail(build.ErrTrailingBytes)
		}
		return dr.stop()
	}
	first := c.pos()
	seg := DataSegment{Index: dr.next, Offset: uint64(first - dr.start)}
	switch flags := c.u32(); flags {
	case 0:
		seg.Addr, seg.AddrKnown = c.constExpr()
	case 1:
		seg.Passive = true
	case 2:
		c.u32() // Memory index.
		seg.Addr, seg.AddrKnown = c.constExpr()
	default:
		if c.err == nil {
			c.fail(build.ErrBadSegmentFlags)
		}
	}
	seg.Size = uint64(c.u32())
	seg.HeaderSize = uint32(c.pos() - first)
	c.skip(seg.Size)
	if c.err != nil {
		return dr.stop()
	}
	dr.next++
	return seg, true
}

func (dr *DataReader) stop() (DataSegment, bool) {
	dr.done, dr.err = true, dr.c.err
	return DataSegment{}, false
}

// Segments rewinds dr and yields each data segment in order of index.
func (dr *DataReader) Segments(yield func(DataSegment) bool) {
	dr.Rewind()
	for seg, ok := dr.Next(); ok && yield(seg); seg, ok = dr.Next() {
	}
}

// Opcodes that may appear in a constant expression, with the extended-const
// proposal's integer arithmetic.
const (
	opEnd         = 0x0b
	opGlobalGet   = 0x23
	opI32Const    = 0x41
	opI64Const    = 0x42
	opF32Const    = 0x43
	opF64Const    = 0x44
	opI32Add      = 0x6a
	opI32Sub      = 0x6b
	opI32Mul      = 0x6c
	opI64Add      = 0x7c
	opI64Sub      = 0x7d
	opI64Mul      = 0x7e
	opRefNull     = 0xd0
	opRefFunc     = 0xd2
	opPrefixSIMD  = 0xfd
	simdV128Const = 12
)

// constExpr skips a constant expression through its end opcode. It reports the
// expression's value when the expression is a lone integer constant, which is
// how a linker places a data segment.
func (c *cursor) constExpr() (v uint64, known bool) {
	for n := 0; c.err == nil; n++ {
		op := c.u8()
		switch op {
		case opEnd:
			if !known || n != 1 {
				return 0, false // Not a lone constant: resolved at instantiation.
			}
			return v, true
		case opI32Const:
			v, known = uint64(uint32(c.sleb(32))), true
		case opI64Const:
			v, known = uint64(c.sleb(64)), true
		case opF32Const:
			c.skip(4)
		case opF64Const:
			c.skip(8)
		case opGlobalGet, opRefFunc:
			c.u32()
		case opRefNull:
			c.sleb(33) // Heap type.
		case opI32Add, opI32Sub, opI32Mul, opI64Add, opI64Sub, opI64Mul:
		case opPrefixSIMD:
			if sub := c.u32(); sub != simdV128Const && c.err == nil {
				c.fail(build.ErrNonConstantSIMD)
			}
			c.skip(16)
		default:
			if c.err == nil {
				c.fail(build.ErrNonConstantExpr)
			}
		}
	}
	return 0, false
}
