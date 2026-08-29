package xdwarf

import (
	"errors"
	"path"
)

// maxTableEntries bounds the directory and file tables decoded from a single
// unit header. The counts come straight from the file, so they need a ceiling
// before they reach make; this mirrors xelf's safechunk guard.
const maxTableEntries = 1 << 20

// strRef locates a string without copying it: names in a line table point into
// .debug_line, .debug_str or .debug_line_str depending on the form used.
type strRef struct {
	sec strSection
	off uint32
	len uint32
}

// fileEntry is one row of a line program's file table.
type fileEntry struct {
	name strRef
	dir  uint64
}

// LineUnit is one compilation unit's line number program: the decoded header
// plus the undecoded opcode stream it introduces.
//
// A unit is a view over the caller's section bytes. It holds its directory and
// file tables as offsets rather than strings, so constructing one costs two
// bounded allocations regardless of how many files the unit names.
type LineUnit struct {
	Version     uint16
	AddressSize uint8
	// Offset is the position of this unit within .debug_line, which is what a
	// compile unit's DW_AT_stmt_list attribute refers to.
	Offset uint64

	// CompDir is the directory relative paths in this unit resolve against.
	//
	// DWARF 5 stores it as directory index 0 of the line table, and it is
	// filled in automatically. DWARF 2-4 stores it as DW_AT_comp_dir on the
	// compilation unit in .debug_info, which this package does not parse, so a
	// caller that wants absolute paths from an older unit must set it. Leaving
	// it empty yields paths relative to the build directory, which is often the
	// more useful form for a size report anyway.
	CompDir string

	dwarf64  bool
	minInst  uint8
	maxOps   uint8
	defStmt  bool
	lineBase int8
	lineRnge uint8
	opBase   uint8
	stdLens  []byte // Operand counts for the standard opcodes.

	dirs  []strRef
	files []fileEntry

	program []byte // Opcode stream, from the end of the header to the end of the unit.
	sec     *Sections
}

// Row is one row of the line table matrix: the state of the line program at a
// point where it emitted an entry.
type Row struct {
	Address uint64
	File    uint64 // Index into the unit's file table.
	Line    uint32
	Column  uint32
	// IsStmt marks a recommended breakpoint location.
	IsStmt bool
	// EndSequence marks the row one past the end of a contiguous address
	// range. Such a row carries no file or line information, and its address
	// is the exclusive upper bound of the preceding sequence.
	EndSequence bool
}

// NumFiles reports the number of entries in the unit's file table.
func (u *LineUnit) NumFiles() int { return len(u.files) }

// FileBase reports the index of the first real file entry. DWARF 5 numbers the
// file table from zero and puts the primary source file at index 0; earlier
// versions number from one and leave index 0 unused.
func (u *LineUnit) FileBase() uint64 {
	if u.Version >= 5 {
		return 0
	}
	return 1
}

// AppendFileName appends the name of file idx to dst, joined with its directory
// when the name is relative. It performs no allocation of its own beyond
// growing dst.
func (u *LineUnit) AppendFileName(dst []byte, idx uint64) ([]byte, error) {
	if idx >= uint64(len(u.files)) {
		return dst, errBadFileIndex
	}
	f := u.files[idx]
	name, err := u.sec.resolve(f.name)
	if err != nil {
		return dst, err
	}
	// An absolute file name stands alone; the directory entry is redundant.
	if isAbs(name) {
		return append(dst, name...), nil
	}

	var dir []byte
	if f.dir < uint64(len(u.dirs)) {
		dir, err = u.sec.resolve(u.dirs[f.dir])
		if err != nil {
			return dst, err
		}
	}
	// Paths nest as comp_dir / include_directory / file_name, but only before
	// DWARF 5. From version 5 the directory table is self-contained -- entry 0
	// is the compilation directory and producers write the other entries
	// relative to wherever they mean -- so joining comp_dir onto a relative
	// directory there would invent a path the producer did not intend. This
	// matches debug/dwarf, which likewise joins only below version 5.
	if u.Version < 5 && !isAbs(dir) && u.CompDir != "" {
		dst = appendPathPart(dst, []byte(u.CompDir))
	}
	dst = appendPathPart(dst, dir)
	return append(dst, name...), nil
}

func isAbs(p []byte) bool { return len(p) > 0 && p[0] == '/' }

// appendPathPart appends a path component and the separator that must follow
// it, doing nothing for an empty component.
func appendPathPart(dst, part []byte) []byte {
	if len(part) == 0 {
		return dst
	}
	dst = append(dst, part...)
	if part[len(part)-1] != '/' {
		dst = append(dst, '/')
	}
	return dst
}

// FileName returns the name of file idx. It allocates; prefer
// [LineUnit.AppendFileName] in a loop.
func (u *LineUnit) FileName(idx uint64) (string, error) {
	b, err := u.AppendFileName(nil, idx)
	return string(b), err
}

func (s *Sections) resolve(r strRef) ([]byte, error) {
	var src []byte
	switch r.sec {
	case strInline:
		src = s.Line
	case strDebugStr:
		src = s.Str
	case strLineStr:
		src = s.LineStr
	default:
		return nil, errBadForm
	}
	end := uint64(r.off) + uint64(r.len)
	if end > uint64(len(src)) {
		return nil, errShortSection
	}
	return src[r.off:end], nil
}

// NextLineUnit decodes the line program unit beginning at off within
// .debug_line, and returns the offset at which the following unit begins.
// Iterate the section by starting at 0 and feeding the returned offset back in
// until it reaches len(s.Line).
func (s *Sections) NextLineUnit(off int) (u LineUnit, next int, err error) {
	if len(s.Line) == 0 {
		return u, 0, errNoLineSection
	}
	if off < 0 || off > len(s.Line) {
		return u, 0, errUnitOutOfRange
	}
	c := &cursor{b: s.Line, off: off, bo: s.byteOrder(), base: 0}

	// Unit length, and with it the 32- vs 64-bit DWARF format.
	unitLen := uint64(c.u32())
	if unitLen == 0xffffffff {
		u.dwarf64 = true
		unitLen = c.u64()
	} else if unitLen >= 0xfffffff0 {
		return u, 0, makeFormatErr(uint64(off), "reserved unit length", unitLen)
	}
	if c.err != nil {
		return u, 0, c.err
	}
	// unit_length counts the bytes after the length field itself.
	unitEnd := uint64(c.off) + unitLen
	if unitEnd > uint64(len(s.Line)) {
		return u, 0, makeFormatErr(uint64(off), "unit overruns section", unitLen)
	}
	u.Offset = uint64(off)
	u.sec = s

	u.Version = c.u16()
	if u.Version < 2 || u.Version > 5 {
		return u, 0, makeFormatErr(uint64(off), errBadVersion.Error(), u.Version)
	}
	if u.Version >= 5 {
		u.AddressSize = c.u8()
		_ = c.u8() // segment_selector_size; segmented addressing is not supported.
	}

	headerLen := c.offset(u.dwarf64)
	// header_length counts from just after itself to the first opcode.
	programStart := uint64(c.off) + headerLen
	if programStart > unitEnd {
		return u, 0, makeFormatErr(uint64(off), "header overruns unit", headerLen)
	}

	u.minInst = c.u8()
	if u.Version >= 4 {
		u.maxOps = c.u8()
	}
	if u.maxOps == 0 {
		u.maxOps = 1
	}
	u.defStmt = c.u8() != 0
	u.lineBase = int8(c.u8())
	u.lineRnge = c.u8()
	u.opBase = c.u8()
	if c.err != nil {
		return u, 0, c.err
	}
	if u.opBase == 0 {
		return u, 0, makeFormatErr(uint64(off), errBadOpcodeBase.Error(), u.opBase)
	}
	u.stdLens = c.bytes(int(u.opBase) - 1)
	if c.err != nil {
		return u, 0, c.err
	}

	if u.Version >= 5 {
		err = u.decodeTablesV5(c)
	} else {
		err = u.decodeTablesV2(c)
	}
	if err != nil {
		return u, 0, err
	}
	if c.err != nil {
		return u, 0, c.err
	}

	// The opcode stream runs from the header's declared end to the unit's end.
	// Trusting header_length rather than where table decoding stopped keeps a
	// producer's padding or an unknown trailing column from derailing us.
	u.program = s.Line[programStart:unitEnd]
	if u.minInst == 0 {
		u.minInst = 1
	}
	if u.lineRnge == 0 {
		u.lineRnge = 1
	}
	return u, int(unitEnd), nil
}

// decodeTablesV2 reads the DWARF 2-4 directory and file tables, which are
// NUL-terminated lists ended by an empty entry.
func (u *LineUnit) decodeTablesV2(c *cursor) error {
	// Directory 0 is the compilation directory, which this table does not
	// carry; leave a blank so indices line up.
	u.dirs = append(u.dirs, strRef{})
	for {
		if c.err != nil {
			return c.err
		}
		off, n := c.cstr()
		if n == 0 {
			break
		}
		if len(u.dirs) >= maxTableEntries {
			return makeFormatErr(uint64(off), "too many directories", len(u.dirs))
		}
		u.dirs = append(u.dirs, strRef{sec: strInline, off: uint32(off), len: uint32(n)})
	}

	// File index 0 is unused before DWARF 5.
	u.files = append(u.files, fileEntry{})
	for {
		if c.err != nil {
			return c.err
		}
		off, n := c.cstr()
		if n == 0 {
			break
		}
		if len(u.files) >= maxTableEntries {
			return makeFormatErr(uint64(off), "too many files", len(u.files))
		}
		dir := c.uleb()
		c.uleb() // mtime
		c.uleb() // length
		u.files = append(u.files, fileEntry{
			name: strRef{sec: strInline, off: uint32(off), len: uint32(n)},
			dir:  dir,
		})
	}
	return c.err
}

// decodeTablesV5 reads the DWARF 5 directory and file tables, which are
// self-describing: a format list names the content type and form of each
// column, then a count, then that many rows.
func (u *LineUnit) decodeTablesV5(c *cursor) error {
	dirs, err := u.decodeEntriesV5(c)
	if err != nil {
		return err
	}
	u.dirs = make([]strRef, len(dirs))
	for i, e := range dirs {
		u.dirs[i] = e.name
	}
	// DWARF 5 carries the compilation directory in the line table as directory
	// 0, so unlike earlier versions no .debug_info lookup is needed.
	if len(u.dirs) > 0 {
		compDir, err := u.sec.resolve(u.dirs[0])
		if err != nil {
			return err
		}
		u.CompDir = string(compDir)
	}
	u.files, err = u.decodeEntriesV5(c)
	return err
}

func (u *LineUnit) decodeEntriesV5(c *cursor) ([]fileEntry, error) {
	formatCount := c.u8()
	if c.err != nil {
		return nil, c.err
	}
	// Each column is a (content type, form) pair. Read them into a small fixed
	// array: DWARF 5 defines five content types, and a sane producer emits each
	// at most once.
	type column struct {
		content LineContent
		form    Form
	}
	var columns [16]column
	if int(formatCount) > len(columns) {
		return nil, makeFormatErr(uint64(c.off), "too many entry format columns", formatCount)
	}
	for i := 0; i < int(formatCount); i++ {
		columns[i].content = LineContent(c.uleb())
		columns[i].form = Form(c.uleb())
	}
	if c.err != nil {
		return nil, c.err
	}

	count := c.uleb()
	if c.err != nil {
		return nil, c.err
	}
	if count > maxTableEntries {
		return nil, makeFormatErr(uint64(c.off), "too many table entries", count)
	}
	entries := make([]fileEntry, 0, count)
	for i := uint64(0); i < count; i++ {
		var e fileEntry
		for j := 0; j < int(formatCount); j++ {
			col := columns[j]
			switch col.content {
			case LineContentPath:
				ref, err := u.decodeStrForm(c, col.form)
				if err != nil {
					return nil, err
				}
				e.name = ref
			case LineContentDirIndex:
				v, err := u.decodeUintForm(c, col.form)
				if err != nil {
					return nil, err
				}
				e.dir = v
			default:
				// Timestamps, sizes and MD5 hashes carry no size information.
				if err := u.skipForm(c, col.form); err != nil {
					return nil, err
				}
			}
		}
		if c.err != nil {
			return nil, c.err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (u *LineUnit) decodeStrForm(c *cursor, f Form) (strRef, error) {
	switch f {
	case FormString:
		off, n := c.cstr()
		return strRef{sec: strInline, off: uint32(off), len: uint32(n)}, c.err
	case FormStrp, FormLineStrp:
		sec := strDebugStr
		if f == FormLineStrp {
			sec = strLineStr
		}
		off := c.offset(u.dwarf64)
		if c.err != nil {
			return strRef{}, c.err
		}
		src := u.sec.Str
		if sec == strLineStr {
			src = u.sec.LineStr
		}
		if off >= uint64(len(src)) {
			return strRef{}, makeFormatErr(off, "string offset past section", len(src))
		}
		// Strings in these sections are NUL-terminated; find the extent once so
		// resolve can hand back a slice.
		end := off
		for end < uint64(len(src)) && src[end] != 0 {
			end++
		}
		return strRef{sec: sec, off: uint32(off), len: uint32(end - off)}, nil
	}
	return strRef{}, makeFormatErr(uint64(c.off), errBadForm.Error(), uint64(f))
}

func (u *LineUnit) decodeUintForm(c *cursor, f Form) (uint64, error) {
	switch f {
	case FormData1:
		return uint64(c.u8()), c.err
	case FormData2:
		return uint64(c.u16()), c.err
	case FormData4:
		return uint64(c.u32()), c.err
	case FormData8:
		return c.u64(), c.err
	case FormUdata:
		return c.uleb(), c.err
	case FormSdata:
		return uint64(c.sleb()), c.err
	}
	return 0, makeFormatErr(uint64(c.off), errBadForm.Error(), uint64(f))
}

func (u *LineUnit) skipForm(c *cursor, f Form) error {
	switch f {
	case FormData1, FormFlag:
		c.bytes(1)
	case FormData2:
		c.bytes(2)
	case FormData4:
		c.bytes(4)
	case FormData8:
		c.bytes(8)
	case FormData16:
		c.bytes(16)
	case FormUdata:
		c.uleb()
	case FormSdata:
		c.sleb()
	case FormString:
		c.cstr()
	case FormStrp, FormLineStrp:
		c.offset(u.dwarf64)
	case FormBlock1:
		c.bytes(int(c.u8()))
	case FormBlock2:
		c.bytes(int(c.u16()))
	case FormBlock4:
		c.bytes(int(c.u32()))
	case FormBlock:
		c.bytes(int(c.uleb()))
	default:
		return makeFormatErr(uint64(c.off), errBadForm.Error(), uint64(f))
	}
	return c.err
}

// ErrStopVisit ends a visit early without reporting an error.
var ErrStopVisit = errors.New("stop visiting")

// VisitRows runs the unit's line number program, calling fn for each row of the
// line table. It allocates nothing: rows are passed by value as the state
// machine produces them.
//
// Returning [ErrStopVisit] from fn ends the walk and returns nil; any other
// error ends the walk and is returned.
func (u *LineUnit) VisitRows(fn func(r Row) error) error {
	c := &cursor{b: u.program, bo: u.sec.byteOrder()}

	// reset returns the state machine to its documented initial state, which
	// applies at the start of the unit and after every end_sequence.
	var row Row
	reset := func() {
		row = Row{File: 1, Line: 1, IsStmt: u.defStmt}
		if u.Version >= 5 {
			row.File = 1 // DWARF 5 also starts at 1, though index 0 is valid.
		}
	}
	reset()

	// advance moves the address by opAdvance operations, honoring VLIW
	// op_index packing when the producer declares more than one op per
	// instruction.
	advance := func(opAdvance uint64) {
		row.Address += uint64(u.minInst) * opAdvance
	}

	for c.err == nil && c.remaining() > 0 {
		opcode := c.u8()
		if c.err != nil {
			break
		}
		switch {
		case opcode >= u.opBase:
			// Special opcode: encodes an address and line delta together.
			adj := uint64(opcode - u.opBase)
			advance(adj / uint64(u.lineRnge))
			row.Line = uint32(int64(row.Line) + int64(u.lineBase) + int64(adj%uint64(u.lineRnge)))
			if err := fn(row); err != nil {
				return stopErr(err)
			}
			row.EndSequence = false

		case opcode == 0:
			// Extended opcode: a length, then a sub-opcode.
			length := c.uleb()
			if c.err != nil {
				break
			}
			if length == 0 {
				continue
			}
			end := c.off + int(length)
			if end > len(c.b) {
				c.fail(makeFormatErr(uint64(c.off), "extended opcode overruns unit", length))
				break
			}
			sub := LineExtOp(c.u8())
			switch sub {
			case LineExtEndSequence:
				row.EndSequence = true
				if err := fn(row); err != nil {
					return stopErr(err)
				}
				reset()
			case LineExtSetAddress:
				switch end - c.off {
				case 8:
					row.Address = c.u64()
				case 4:
					row.Address = uint64(c.u32())
				case 2:
					row.Address = uint64(c.u16())
				default:
					c.fail(makeFormatErr(uint64(c.off), "unsupported address size", end-c.off))
				}
			default:
				// define_file, set_discriminator and vendor extensions carry
				// nothing this package needs; the length lets us skip them.
			}
			c.off = end

		default:
			switch LineOp(opcode) {
			case LineOpCopy:
				if err := fn(row); err != nil {
					return stopErr(err)
				}
				row.EndSequence = false
			case LineOpAdvancePC:
				advance(c.uleb())
			case LineOpAdvanceLine:
				row.Line = uint32(int64(row.Line) + c.sleb())
			case LineOpSetFile:
				row.File = c.uleb()
			case LineOpSetColumn:
				row.Column = uint32(c.uleb())
			case LineOpNegateStmt:
				row.IsStmt = !row.IsStmt
			case LineOpSetBasicBlock:
				// No state this package tracks.
			case LineOpConstAddPC:
				advance(uint64(255-u.opBase) / uint64(u.lineRnge))
			case LineOpFixedAdvancePC:
				// Deliberately not scaled by minimum_instruction_length.
				row.Address += uint64(c.u16())
			case LineOpSetPrologueEnd, LineOpSetEpilogueBeg:
				// No state this package tracks.
			case LineOpSetISA:
				c.uleb()
			default:
				// An unknown standard opcode still declares its operand count,
				// so the stream stays parseable.
				if int(opcode) <= len(u.stdLens) {
					for i := uint8(0); i < u.stdLens[opcode-1]; i++ {
						c.uleb()
					}
				} else {
					c.fail(makeFormatErr(uint64(c.off), "unknown standard opcode", opcode))
				}
			}
		}
	}
	return c.err
}

func stopErr(err error) error {
	if errors.Is(err, ErrStopVisit) {
		return nil
	}
	return err
}

// CleanPath normalizes a source path for reporting. Compilers emit a mix of
// absolute paths, "./" prefixes and ".." segments for the same file, which
// would otherwise show up as distinct rows in a size report.
func CleanPath(p string) string {
	if p == "" {
		return p
	}
	return path.Clean(p)
}
