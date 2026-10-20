package xwasm

import (
	"io"

	"github.com/soypat/tinyboot/build"
)

// Subsection ids of the "name" custom section, from the extended name section
// proposal. Each is optional and at most one of each appears, in order.
const (
	nameSubModule   = 0
	nameSubFunction = 1
	nameSubGlobal   = 7
	nameSubData     = 9
)

// NameMap identifies one of the name section's maps from index to name.
type NameMap uint8

const (
	NameMapFuncs   NameMap = nameSubFunction
	NameMapGlobals NameMap = nameSubGlobal
	NameMapData    NameMap = nameSubData
)

// NameEntry is one entry of a name map: the index it names, and where the name
// lies in the module. Len sizes the buffer [NameReader.ReadName] reads it into.
type NameEntry struct {
	Index uint32
	Off   uint64 // File offset of the name's bytes.
	Len   uint32
}

// NameReader walks the name maps in a module's "name" custom section through a
// caller-owned window. Names are skipped, not read: each entry says where its
// name lies and how long it is, and [NameReader.ReadName] reads it into a
// buffer the caller sized from that. One map at a time is walked, entry by entry
// with [NameReader.Open] and [NameReader.Next], or all at once with
// [NameReader.FuncNames] and its siblings.
//
// A NameReader is reusable: [NameReader.Reset] points it at another module and
// keeps the window. The window belongs to the reader from Reset until the next
// Reset; lending it to another reader in between corrupts both walks.
type NameReader struct {
	c      cursor
	start  int64
	secEnd int64 // End of the name section; c.end is the open map's end.
	ok     bool  // Module has a name section.
	// The open map.
	count, next uint32
	last        uint32 // Index of the previous entry, to check ordering.
	done        bool
	err         error
}

// Reset points nr at f's "name" section, reading through buf, which need only
// hold a section's framing; a shorter buf fails with [io.ErrShortBuffer]. A
// module with no name section yields no names.
func (nr *NameReader) Reset(f *File, buf []byte) error {
	if len(buf) < maxSectionFrame {
		return io.ErrShortBuffer
	}
	*nr = NameReader{c: nr.c, done: true}
	sec, err := f.SectionByName("name")
	if err != nil || sec.SectionHeader().ID != SecCustom {
		nr.c.reset(f.r, buf, 0, 0)
		return nil
	}
	sh := sec.SectionHeader()
	nr.start, nr.secEnd = int64(sh.Offset), int64(sh.End())
	nr.ok = true
	nr.c.reset(f.r, buf, nr.start, nr.secEnd)
	return nil
}

// Err returns why the walk stopped early, or nil if it ran to completion or the
// caller stopped it.
func (nr *NameReader) Err() error { return nr.err }

// Open positions nr before the first entry of map m, for [NameReader.Next]. A
// module without the map yields no entries.
func (nr *NameReader) Open(m NameMap) {
	nr.err, nr.count, nr.next, nr.done = nil, 0, 0, true
	if !nr.ok {
		return
	}
	c := &nr.c
	c.err, c.end = nil, nr.secEnd
	c.seek(nr.start)
	for c.err == nil && c.pos() < c.end {
		id := c.u8()
		size := c.u32()
		subEnd := c.pos() + int64(size)
		if c.err != nil {
			break
		} else if subEnd > c.end {
			c.fail(build.ErrSubsectionTooLarge)
			break
		}
		if id != uint8(m) {
			c.seek(subEnd)
			continue
		}
		c.end = subEnd // Bound the name map by its subsection.
		// An entry is at least a one-byte index and a one-byte empty name.
		nr.count = c.vecLen(2)
		nr.done = false
		break // At most one subsection of each kind.
	}
	nr.err = c.err
}

// Next returns the open map's next entry, in increasing order of index as the
// format requires. It reports false once the entries run out or the walk
// fails; [NameReader.Err] tells which.
func (nr *NameReader) Next() (NameEntry, bool) {
	if nr.done {
		return NameEntry{}, false
	}
	c := &nr.c
	if nr.next == nr.count {
		if c.err == nil && c.pos() != c.end {
			c.fail(build.ErrTrailingBytes)
		}
		return nr.stop()
	}
	e := NameEntry{Index: c.u32(), Len: c.u32()}
	e.Off = uint64(c.pos())
	c.skip(uint64(e.Len))
	if c.err == nil && nr.next > 0 && e.Index <= nr.last {
		c.fail(build.ErrNamesOutOfOrder)
	}
	if c.err != nil {
		return nr.stop()
	}
	nr.last = e.Index
	nr.next++
	return e, true
}

func (nr *NameReader) stop() (NameEntry, bool) {
	nr.done, nr.err = true, nr.c.err
	return NameEntry{}, false
}

// ReadName reads e's name into dst, which e.Len sizes, and returns its length.
// A dst too short for the name fails with [io.ErrShortBuffer]. It reads around
// the walk's window, so it may be called mid-walk.
func (nr *NameReader) ReadName(dst []byte, e NameEntry) (int, error) {
	n := int(e.Len)
	if n > len(dst) {
		return 0, io.ErrShortBuffer
	}
	if got, err := nr.c.wr.ReaderAt().ReadAt(dst[:n], int64(e.Off)); got < n {
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	return n, nil
}

// FuncNames yields each named function's entry, in increasing order of index as
// the format requires. Functions the section does not name are skipped.
func (nr *NameReader) FuncNames(yield func(NameEntry) bool) {
	nr.walk(NameMapFuncs, yield)
}

// DataNames yields each named data segment's entry, as FuncNames does for
// functions. wasm-ld names segments after the output section they came from:
// ".rodata", ".data".
func (nr *NameReader) DataNames(yield func(NameEntry) bool) {
	nr.walk(NameMapData, yield)
}

// GlobalNames yields each named global's entry, as FuncNames does for
// functions.
func (nr *NameReader) GlobalNames(yield func(NameEntry) bool) {
	nr.walk(NameMapGlobals, yield)
}

func (nr *NameReader) walk(m NameMap, yield func(NameEntry) bool) {
	nr.Open(m)
	for e, ok := nr.Next(); ok && yield(e); e, ok = nr.Next() {
	}
}
