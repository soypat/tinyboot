package xwasm

// Subsection ids of the "name" custom section, from the extended name section
// proposal. Each is optional and at most one of each appears, in order.
const (
	nameSubModule   = 0
	nameSubFunction = 1
	nameSubGlobal   = 7
	nameSubData     = 9
)

// NameReader walks the name maps in a module's "name" custom section
// through a caller-owned buffer. Names are presented in place, borrowed from
// the buffer, so a walk allocates nothing.
//
// A NameReader is reusable: [NameReader.Reset] points it at another module and
// keeps the buffer. The buffer belongs to the reader from Reset until the next
// Reset; lending it to another reader in between corrupts both walks.
type NameReader struct {
	c     cursor
	start int64
	ok    bool // Module has a name section.
	err   error
}

// Reset points nr at f's "name" section, reading through buf. The longest
// function name must fit in buf; a longer one stops the walk with a
// [BufferTooSmallError], and the caller can grow buf and walk again. A module
// with no name section yields no names.
func (nr *NameReader) Reset(f *File, buf []byte) error {
	if len(buf) < maxSectionFrame {
		return BufferTooSmallError{Need: maxSectionFrame, Have: len(buf)}
	}
	*nr = NameReader{c: nr.c}
	sec, err := f.SectionByName("name")
	if err != nil || sec.SectionHeader().ID != SecCustom {
		nr.c.reset(f.r, buf, 0, 0)
		return nil
	}
	sh := sec.SectionHeader()
	nr.start = int64(sh.Offset)
	nr.ok = true
	nr.c.reset(f.r, buf, nr.start, int64(sh.End()))
	return nil
}

// Err returns why the last walk stopped early, or nil if it ran to completion
// or the caller stopped it.
func (nr *NameReader) Err() error { return nr.err }

// FuncNames yields each named function's index and name, in increasing order
// of index as the format requires. name is valid only until the next yield.
// Functions the section does not name are skipped.
func (nr *NameReader) FuncNames(yield func(idx uint32, name []byte) bool) {
	nr.nameMap(nameSubFunction, yield)
}

// DataNames yields each named data segment's index and name, as FuncNames
// does for functions. wasm-ld names segments after the output section they
// came from: ".rodata", ".data".
func (nr *NameReader) DataNames(yield func(idx uint32, name []byte) bool) {
	nr.nameMap(nameSubData, yield)
}

// GlobalNames yields each named global's index and name, as FuncNames does for
// functions.
func (nr *NameReader) GlobalNames(yield func(idx uint32, name []byte) bool) {
	nr.nameMap(nameSubGlobal, yield)
}

// nameMap walks the name map in subsection sub.
func (nr *NameReader) nameMap(sub uint8, yield func(idx uint32, name []byte) bool) {
	nr.err = nil
	if !nr.ok {
		return
	}
	c := &nr.c
	c.err = nil
	c.seek(nr.start)
	for c.err == nil && c.pos() < c.end {
		id := c.u8()
		size := c.u32()
		subEnd := c.pos() + int64(size)
		if c.err != nil {
			break
		} else if subEnd > c.end {
			c.fail(makeFormatErr(uint64(c.pos()), "name subsection exceeds section", size))
			break
		}
		if id != sub {
			c.seek(subEnd)
			continue
		}
		saved := c.end
		c.end = subEnd // Bound the name map by its subsection.
		// An entry is at least a one-byte index and a one-byte empty name.
		count := c.vecLen(2)
		var last uint32
		for i := uint32(0); i < count && c.err == nil; i++ {
			idx := c.u32()
			name := c.view(uint64(c.u32()))
			if c.err != nil {
				break
			}
			if i > 0 && idx <= last {
				c.fail(makeFormatErr(uint64(c.pos()), "names out of order", idx))
				break
			}
			last = idx
			if !yield(idx, name) {
				// Lift the bound here too, or the next walk sees only this
				// subsection.
				c.end = saved
				return
			}
		}
		if c.err == nil && c.pos() != subEnd {
			c.fail(makeFormatErr(uint64(c.pos()), "trailing bytes in name map", subEnd-c.pos()))
		}
		c.end = saved
		break // At most one subsection of each kind.
	}
	nr.err = c.err
}
