package xwasm

import (
	"io"
	"math"

	"github.com/soypat/tinyboot/build"
)

// Func locates one function body in the Code section.
type Func struct {
	// Index is the function's index in the module's function index space,
	// where imported functions come first: the body's ordinal plus
	// [File.NumImportedFuncs]. The name section keys names by this index.
	Index uint32
	// Offset is the position of the body's size prefix, measured from the start
	// of the Code section's contents. DWARF addresses in a WebAssembly module
	// are measured from the same point, but a subprogram's DW_AT_low_pc names
	// the body proper: [Func.BodyOffset].
	Offset uint64
	// PrefixSize is the length of the size prefix, 1 to 5 bytes.
	PrefixSize uint8
	// Size is the body's size in bytes, excluding the prefix.
	Size uint64
}

// BodyOffset returns the offset of the body proper -- its local declarations,
// then its code -- from the start of the Code section's contents.
func (fn Func) BodyOffset() uint64 { return fn.Offset + uint64(fn.PrefixSize) }

// End returns the offset one past the body's last byte, from the start of the
// Code section's contents.
func (fn Func) End() uint64 { return fn.BodyOffset() + fn.Size }

// CodeReader walks the function bodies of a module's Code section through a
// caller-owned buffer, without holding anything per function. Bodies come one
// at a time from [CodeReader.Next], or all at once from [CodeReader.Funcs].
//
// A CodeReader is reusable: [CodeReader.Reset] points it at another module and
// keeps the buffer. The buffer belongs to the reader from Reset until the next
// Reset; lending it to another reader in between corrupts both walks.
type CodeReader struct {
	c        cursor
	start    int64 // File offset of the Code section's contents.
	count    uint32
	imported uint32
	next     uint32 // Ordinal of the body Next reads.
	done     bool
	err      error
}

// Reset points cr at f's Code section, reading through buf, and rewinds it to
// the first body. buf only needs to hold a few bytes at a time: bodies are
// skipped, never read. Larger buffers mean fewer reads. A module with no Code
// section yields no functions.
func (cr *CodeReader) Reset(f *File, buf []byte) error {
	if len(buf) < maxSectionFrame {
		return io.ErrShortBuffer
	}
	imported, err := f.NumImportedFuncs()
	if err != nil {
		return err
	}
	*cr = CodeReader{c: cr.c, imported: imported}
	sec, err := f.SectionByID(SecCode)
	if err != nil {
		cr.c.reset(f.r, buf, 0, 0)
		cr.Rewind()
		return nil
	}
	sh := sec.SectionHeader()
	cr.start = int64(sh.Offset)
	cr.c.reset(f.r, buf, cr.start, int64(sh.End()))
	// Every body takes at least its one-byte size prefix and one byte of local
	// declaration count.
	cr.count = cr.c.vecLen(2)
	if cr.c.err != nil {
		return cr.c.err
	}
	if uint64(imported)+uint64(cr.count) > math.MaxUint32 {
		return build.ErrIndexSpaceOverflow
	}
	cr.Rewind()
	return nil
}

// NumFuncs returns the number of function bodies in the Code section.
func (cr *CodeReader) NumFuncs() uint32 { return cr.count }

// NumImportedFuncs returns the number of imported functions, which precede the
// module's own in the function index space.
func (cr *CodeReader) NumImportedFuncs() uint32 { return cr.imported }

// Err returns why the walk stopped early, or nil if it ran to completion or the
// caller stopped it.
func (cr *CodeReader) Err() error { return cr.err }

// Rewind positions cr before the first body, to walk the bodies anew.
func (cr *CodeReader) Rewind() {
	c := &cr.c
	cr.err, cr.next, cr.done = nil, 0, cr.count == 0
	if cr.done {
		return
	}
	c.err = nil
	c.seek(cr.start)
	c.u32() // Count, validated by Reset.
}

// Next returns the next function body in order of index. It reports false once
// the bodies run out or the walk fails; [CodeReader.Err] tells which.
func (cr *CodeReader) Next() (Func, bool) {
	if cr.done {
		return Func{}, false
	}
	c := &cr.c
	if cr.next == cr.count {
		if c.err == nil && c.pos() != c.end {
			c.fail(build.ErrTrailingBytes)
		}
		return cr.stop()
	}
	prefix := c.pos()
	size := c.u32()
	fn := Func{
		Index:      cr.imported + cr.next,
		Offset:     uint64(prefix - cr.start),
		PrefixSize: uint8(c.pos() - prefix),
		Size:       uint64(size),
	}
	c.skip(fn.Size)
	if c.err != nil {
		return cr.stop()
	}
	cr.next++
	return fn, true
}

func (cr *CodeReader) stop() (Func, bool) {
	cr.done, cr.err = true, cr.c.err
	return Func{}, false
}

// Funcs rewinds cr and yields each function body in order of index.
func (cr *CodeReader) Funcs(yield func(Func) bool) {
	cr.Rewind()
	for fn, ok := cr.Next(); ok && yield(fn); fn, ok = cr.Next() {
	}
}

// Import descriptor kinds.
const (
	importFunc   = 0x00
	importTable  = 0x01
	importMemory = 0x02
	importGlobal = 0x03
	importTag    = 0x04
)

// NumImportedFuncs walks the Import section and counts the imported functions.
// A module with no Import section imports none.
func (f *File) NumImportedFuncs() (uint32, error) {
	sec, err := f.SectionByID(SecImport)
	if err == build.ErrSectionNotFound {
		return 0, nil
	}
	sh := sec.SectionHeader()
	var c cursor
	c.reset(f.r, f.buf[:], int64(sh.Offset), int64(sh.End()))
	// An import is at least two empty names and a kind byte with a one-byte
	// operand.
	count := c.vecLen(4)
	var funcs uint32
	for i := uint32(0); i < count && c.err == nil; i++ {
		c.skipName() // Module.
		c.skipName() // Field.
		switch kind := c.u8(); kind {
		case importFunc:
			c.u32() // Type index.
			funcs++
		case importTable:
			c.valType()
			c.limits()
		case importMemory:
			c.limits()
		case importGlobal:
			c.valType()
			c.u8() // Mutability.
		case importTag:
			c.u8()  // Attribute.
			c.u32() // Type index.
		default:
			if c.err == nil {
				c.fail(build.ErrUnknownImportKind)
			}
		}
	}
	if c.err == nil && c.pos() != c.end {
		c.fail(build.ErrTrailingBytes)
	}
	if c.err == io.EOF {
		c.err = io.ErrUnexpectedEOF
	}
	return funcs, c.err
}
