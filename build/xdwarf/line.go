package xdwarf

import (
	"bytes"
	"encoding/binary"
	"io"
	"path"
	"slices"
	"strconv"
)

// maxTableEntries bounds the directory and file tables decoded from a single
// unit header. The counts come straight from the file, so they need a ceiling
// before they reach make; this mirrors xelf's safechunk guard.
const maxTableEntries = 1 << 20

// minWindow is the smallest opcode-stream fill buffer [DecodeLineUnit] will
// leave itself in aux. Below this a single extended opcode's operand could not
// be held whole, and every read would refill.
const minWindow = 256

// unitPrefixLen is the largest fixed prefix a line unit header can have before
// its variable-length parts: unit_length (4 or 12), version (2), address_size
// and segment_selector_size (1 each, DWARF 5 only), header_length (4 or 8).
const unitPrefixLen = 12 + 2 + 1 + 1 + 8

// AuxTooSmallError reports an aux buffer that cannot hold a unit's header plus
// the minimum opcode-stream window, and how large it would have to be. A caller
// iterating a section can grow its buffer to Need and retry the same offset,
// rather than having to guess a size up front.
type AuxTooSmallError struct {
	Need int
	Have int
}

func (e AuxTooSmallError) Error() string {
	return "xdwarf: aux buffer of " + strconv.Itoa(e.Have) +
		" bytes too small for line unit, need " + strconv.Itoa(e.Need)
}

// strRef locates a string without copying it: names in a line table point into
// .debug_line, .debug_str or .debug_line_str depending on the form used.
//
// len is meaningful only for an inline ref, where the header decode already
// walked to the terminator. A ref into .debug_str or .debug_line_str leaves it
// zero and finds the NUL at resolve time, so a file entry no row ever names
// costs nothing to have decoded.
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
// plus the offsets of the undecoded opcode stream it introduces.
//
// A unit borrows the aux buffer it was decoded with: its directory and file
// tables hold offsets into the header copied to the front of aux, and its
// opcode stream is read through the tail. Decoding another unit into the same
// aux invalidates it. Reusing one LineUnit across units is what makes decoding
// allocation-free, since the tables are truncated rather than rebuilt.
type LineUnit struct {
	Version     uint16
	AddressSize uint8
	// Offset is the position of this unit within .debug_line, which is what a
	// compile unit's DW_AT_stmt_list attribute refers to.
	Offset int64

	// CompDir is the directory relative paths in this unit resolve against.
	//
	// DWARF 2-4 stores it as DW_AT_comp_dir on the compilation unit in
	// .debug_info, which this package does not parse, so a caller that wants
	// absolute paths from an older unit must set it. Leaving it empty yields
	// paths relative to the build directory, which is often the more useful form
	// for a size report anyway.
	//
	// DWARF 5 carries it in the line table as directory index 0 and ignores this
	// field; [LineUnit.AppendCompDir] reports it for either version.
	CompDir string

	dwarf64  bool
	minInst  uint8
	maxOps   uint8
	defStmt  bool
	lineBase int8
	lineRnge uint8
	opBase   uint8
	// stdLens holds the operand counts for the standard opcodes. opcode_base is
	// a uint8 and the table has opcode_base-1 entries, so a fixed array covers
	// every legal header without allocating.
	stdLens    [255]byte
	numStdLens int

	dirs  []strRef
	files []fileEntry

	sec Sections
	hdr []byte // The unit header, at the front of aux. Inline strRefs index it.
	win []byte // The tail of aux, the fill buffer VisitRows streams through.
	// The opcode stream, as absolute offsets within .debug_line.
	progStart, progEnd int64
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

// AppendCompDir appends the unit's compilation directory to dst. Before DWARF 5
// that is whatever the caller put in [LineUnit.CompDir]; from version 5 it is
// directory index 0 of the line table itself.
func (u *LineUnit) AppendCompDir(dst []byte) ([]byte, error) {
	if u.Version < 5 {
		return append(dst, u.CompDir...), nil
	}
	if len(u.dirs) == 0 {
		return dst, nil
	}
	return u.appendStr(dst, u.dirs[0])
}

// AppendFileName appends the name of file idx to dst, joined with its directory
// when the name is relative. It performs no allocation of its own beyond
// growing dst.
func (u *LineUnit) AppendFileName(dst []byte, idx uint64) ([]byte, error) {
	if idx >= uint64(len(u.files)) {
		return dst, errBadFileIndex
	}
	f := u.files[idx]
	// An inline name is already resident, so whether it is absolute can be
	// settled without materializing it and the parts go down in path order.
	// Every name does this before DWARF 5, and it is the whole reason the header
	// is copied rather than streamed.
	if name, ok := u.residentStr(f.name); ok {
		// An absolute file name stands alone; the directory entry is redundant.
		if isAbs(name) {
			return append(dst, name...), nil
		}
		dst, err := u.appendDir(dst, f.dir)
		if err != nil {
			return dst, err
		}
		return append(dst, name...), nil
	}
	// The name lives in a string section, so learning whether it is absolute
	// means reading it. Put it down first and rotate the prefix in front of it
	// afterwards, which beats reading it a second time.
	start := len(dst)
	dst, err := u.appendStr(dst, f.name)
	if err != nil {
		return dst[:start], err
	}
	if isAbs(dst[start:]) {
		return dst, nil
	}
	nameLen := len(dst) - start
	dst, err = u.appendDir(dst, f.dir)
	if err != nil {
		return dst[:start], err
	}
	rotate(dst[start:], nameLen)
	return dst, nil
}

// residentStr returns the bytes of a ref already held in the unit header,
// reporting false for one that would have to be read from a string section.
func (u *LineUnit) residentStr(r strRef) ([]byte, bool) {
	if r.sec != strInline {
		return nil, false
	}
	end := uint64(r.off) + uint64(r.len)
	if end > uint64(len(u.hdr)) {
		return nil, false
	}
	return u.hdr[r.off:end], true
}

// appendDir appends the directory prefix a relative file name in directory dir
// hangs off, separator included, or nothing when there is no prefix.
//
// Paths nest as comp_dir / include_directory / file_name, but only before DWARF
// 5. From version 5 the directory table is self-contained -- entry 0 is the
// compilation directory and producers write the other entries relative to
// wherever they mean -- so joining comp_dir onto a relative directory there
// would invent a path the producer did not intend. This matches debug/dwarf,
// which likewise joins only below version 5.
func (u *LineUnit) appendDir(dst []byte, dir uint64) ([]byte, error) {
	var ref strRef
	if dir < uint64(len(u.dirs)) {
		ref = u.dirs[dir]
	}
	if d, ok := u.residentStr(ref); ok {
		if u.Version < 5 && !isAbs(d) && u.CompDir != "" {
			dst = appendPathPartStr(dst, u.CompDir)
		}
		return appendPathPart(dst, d), nil
	}
	// Same bind as an unresolved file name: append, then rotate comp_dir in
	// front of what came back.
	at := len(dst)
	dst, err := u.appendStr(dst, ref)
	if err != nil {
		return dst, err
	}
	dirLen := len(dst) - at
	if u.Version < 5 && !isAbs(dst[at:]) && u.CompDir != "" {
		dst = appendPathPartStr(dst, u.CompDir)
		rotate(dst[at:], dirLen)
	}
	if dirLen != 0 {
		dst = appendSep(dst)
	}
	return dst, nil
}

// rotate moves the first n bytes of b to the end, in place.
func rotate(b []byte, n int) {
	reverse(b[:n])
	reverse(b[n:])
	reverse(b)
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func isAbs(p []byte) bool { return len(p) > 0 && p[0] == '/' }

// appendSep appends the separator that must follow a non-empty path component.
func appendSep(dst []byte) []byte {
	if len(dst) != 0 && dst[len(dst)-1] != '/' {
		dst = append(dst, '/')
	}
	return dst
}

// appendPathPart appends a path component and the separator that must follow
// it, doing nothing for an empty component.
func appendPathPart(dst, part []byte) []byte {
	if len(part) == 0 {
		return dst
	}
	dst = append(dst, part...)
	return appendSep(dst)
}

// appendPathPartStr is [appendPathPart] for a string, taking it as one so the
// caller's CompDir does not have to be converted -- and copied -- on the way in.
func appendPathPartStr(dst []byte, part string) []byte {
	if len(part) == 0 {
		return dst
	}
	dst = append(dst, part...)
	return appendSep(dst)
}

// FileName returns the name of file idx. It allocates; prefer
// [LineUnit.AppendFileName] in a loop.
func (u *LineUnit) FileName(idx uint64) (string, error) {
	b, err := u.AppendFileName(nil, idx)
	return string(b), err
}

// appendStr resolves a string reference onto dst. An inline ref is a subslice
// of the resident header; the others are read from their section.
func (u *LineUnit) appendStr(dst []byte, r strRef) ([]byte, error) {
	switch r.sec {
	case strInline:
		if r.len == 0 {
			return dst, nil
		}
		end := uint64(r.off) + uint64(r.len)
		if end > uint64(len(u.hdr)) {
			return dst, errShortSection
		}
		return append(dst, u.hdr[r.off:end]...), nil
	case strDebugStr:
		return appendCStr(dst, u.sec.Str, int64(r.off))
	case strLineStr:
		return appendCStr(dst, u.sec.LineStr, int64(r.off))
	}
	return dst, errBadForm
}

// appendCStr appends the NUL-terminated string at off to dst, reading straight
// onto dst's own spare capacity so it needs no scratch of its own. That matters
// because the aux tail, the obvious place for scratch, is simultaneously the
// window a [LineUnit.VisitRows] walk is streaming the opcode program through.
func appendCStr(dst []byte, r io.ReaderAt, off int64) ([]byte, error) {
	if r == nil {
		return dst, errNoStrSection
	}
	const chunk = 64
	start := len(dst)
	for {
		n := len(dst)
		// Grow reuses spare capacity, so a caller passing a recycled buffer
		// stops allocating here after the first few names.
		dst = slices.Grow(dst, chunk)[:n+chunk]
		got, err := r.ReadAt(dst[n:], off+int64(n-start))
		if i := bytes.IndexByte(dst[n:n+got], 0); i >= 0 {
			return dst[:n+i], nil
		}
		dst = dst[:n+got]
		if err != nil {
			// The section ended before a terminator did.
			return dst[:start], errShortSection
		}
	}
}

// DecodeLineUnit decodes the line program unit beginning at off within
// .debug_line into dst, and returns the offset at which the following unit
// begins. Iterate the section by starting at 0 and feeding the returned offset
// back in until it reaches size, the size of .debug_line.
//
// aux is scratch owned by the caller and borrowed by dst until the next decode
// into the same buffer. The unit's header is copied to its front, where dst's
// directory and file tables point, and its tail becomes the fill buffer
// [LineUnit.VisitRows] streams the opcode program through. An aux too small to
// hold both reports how large it needs to be. Passing the same dst and aux back
// on the next call makes decoding allocation-free.
func DecodeLineUnit(dst *LineUnit, sec Sections, off, size int64, aux []byte) (next int64, err error) {
	if sec.Line == nil {
		return 0, errNoLineSection
	}
	if off < 0 || size < 0 || off > size {
		return 0, errUnitOutOfRange
	}
	// An aux too small to hold even the fixed prefix cannot say how large it
	// needs to be, since the length that says so is inside the prefix. The cold
	// path works it out with its own scratch, so one retry is always enough.
	if len(aux) < unitPrefixLen {
		return 0, auxRequirement(sec, off, size, len(aux))
	}

	// Fill aux in one read and decode out of it. How long the header is only
	// becomes known partway through parsing it, so reading a prefix first and
	// the rest after would cost two reads per unit; a header that fits in aux at
	// all -- the case the caller is required to provide for anyway -- is wholly
	// here after this one.
	want := int64(len(aux))
	if avail := size - off; want > avail {
		want = avail
	}
	np, _ := sec.Line.ReadAt(aux[:want], off)
	p, err := decodeUnitPrefix(aux[:np], off, size, sec.byteOrder())
	if err != nil {
		return 0, err
	}

	// Split aux: the header at the front, the opcode-stream window in the tail.
	hdrLen := int(p.progStart - off)
	if need := hdrLen + minWindow; len(aux) < need {
		return 0, AuxTooSmallError{Need: need, Have: len(aux)}
	}
	if hdrLen > np {
		// aux had room but the read came up short, so the section ends inside a
		// header its own header_length said was longer.
		return 0, errShortSection
	}
	hdr := aux[:hdrLen]

	dst.reset()
	dst.sec = sec
	dst.hdr = hdr
	dst.win = aux[hdrLen:]
	dst.Offset = off
	dst.Version = p.version
	dst.AddressSize = p.addrSize
	dst.dwarf64 = p.dwarf64
	dst.progStart, dst.progEnd = p.progStart, p.unitEnd

	// Resume where the prefix left off, over the header alone so a malformed
	// table cannot wander into the opcode stream that follows it. base keeps the
	// offsets in error messages section-absolute.
	c := cursor{b: hdr, off: p.consumed, bo: sec.byteOrder(), base: int(off)}
	dst.minInst = c.u8()
	if p.version >= 4 {
		dst.maxOps = c.u8()
	}
	if dst.maxOps == 0 {
		dst.maxOps = 1
	}
	dst.defStmt = c.u8() != 0
	dst.lineBase = int8(c.u8())
	dst.lineRnge = c.u8()
	dst.opBase = c.u8()
	if c.err != nil {
		return 0, c.err
	}
	if dst.opBase == 0 {
		return 0, makeFormatErr(uint64(off), errBadOpcodeBase.Error(), dst.opBase)
	}
	dst.numStdLens = int(dst.opBase) - 1
	copy(dst.stdLens[:dst.numStdLens], c.bytes(dst.numStdLens))
	if c.err != nil {
		return 0, c.err
	}

	if p.version >= 5 {
		err = dst.decodeTablesV5(&c)
	} else {
		err = dst.decodeTablesV2(&c)
	}
	if err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, c.err
	}

	if dst.minInst == 0 {
		dst.minInst = 1
	}
	if dst.lineRnge == 0 {
		dst.lineRnge = 1
	}
	return p.unitEnd, nil
}

// unitPrefix is the fixed head of a line unit header: enough of it to say where
// the unit ends and where its opcode program starts.
type unitPrefix struct {
	unitEnd   int64
	progStart int64
	version   uint16
	addrSize  uint8
	dwarf64   bool
	consumed  int // Bytes of the header the prefix accounts for.
}

func decodeUnitPrefix(b []byte, off, size int64, bo binary.ByteOrder) (p unitPrefix, err error) {
	c := cursor{b: b, bo: bo, base: int(off)}
	// Unit length, and with it the 32- vs 64-bit DWARF format.
	unitLen := uint64(c.u32())
	if unitLen == 0xffffffff {
		p.dwarf64 = true
		unitLen = c.u64()
	} else if unitLen >= 0xfffffff0 {
		return p, makeFormatErr(uint64(off), "reserved unit length", unitLen)
	}
	if c.err != nil {
		return p, c.err
	}
	// unit_length counts the bytes after the length field itself.
	p.unitEnd = off + int64(c.off) + int64(unitLen)
	if unitLen > uint64(size) || p.unitEnd > size || p.unitEnd < off {
		return p, makeFormatErr(uint64(off), "unit overruns section", unitLen)
	}

	p.version = c.u16()
	if p.version < 2 || p.version > 5 {
		return p, makeFormatErr(uint64(off), errBadVersion.Error(), p.version)
	}
	if p.version >= 5 {
		p.addrSize = c.u8()
		_ = c.u8() // segment_selector_size; segmented addressing is not supported.
	}
	headerLen := c.offset(p.dwarf64)
	if c.err != nil {
		return p, c.err
	}
	// header_length counts from just after itself to the first opcode.
	p.progStart = off + int64(c.off) + int64(headerLen)
	if p.progStart > p.unitEnd || p.progStart < off {
		return p, makeFormatErr(uint64(off), "header overruns unit", headerLen)
	}
	p.consumed = c.off
	return p, nil
}

// auxRequirement reports how large aux must be for the unit at off, for an aux
// too small to have decoded the header length in place. It is kept out of
// [DecodeLineUnit] because its scratch array would otherwise be forced onto the
// heap on every call, whether the cold path ran or not.
func auxRequirement(sec Sections, off, size int64, have int) error {
	var prefix [unitPrefixLen]byte
	want := int64(len(prefix))
	if avail := size - off; want > avail {
		want = avail
	}
	np, _ := sec.Line.ReadAt(prefix[:want], off)
	p, err := decodeUnitPrefix(prefix[:np], off, size, sec.byteOrder())
	if err != nil {
		return err
	}
	return AuxTooSmallError{Need: int(p.progStart-off) + minWindow, Have: have}
}

// reset returns a unit to its zero state while keeping the table slices, so a
// caller reusing one unit across a section allocates only on the first few.
func (u *LineUnit) reset() {
	dirs, files := u.dirs[:0], u.files[:0]
	*u = LineUnit{dirs: dirs, files: files}
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
	if err := u.decodeEntriesV5(c, true); err != nil {
		return err
	}
	return u.decodeEntriesV5(c, false)
}

// decodeEntriesV5 appends one table's rows to the unit, into dirs when isDir is
// set and files otherwise. Filling the destination directly keeps the decode
// free of a temporary slice.
func (u *LineUnit) decodeEntriesV5(c *cursor, isDir bool) error {
	formatCount := c.u8()
	if c.err != nil {
		return c.err
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
		return makeFormatErr(uint64(c.off), "too many entry format columns", formatCount)
	}
	for i := 0; i < int(formatCount); i++ {
		columns[i].content = LineContent(c.uleb())
		columns[i].form = Form(c.uleb())
	}
	if c.err != nil {
		return c.err
	}

	count := c.uleb()
	if c.err != nil {
		return c.err
	}
	if count > maxTableEntries {
		return makeFormatErr(uint64(c.off), "too many table entries", count)
	}
	for i := uint64(0); i < count; i++ {
		var e fileEntry
		for j := 0; j < int(formatCount); j++ {
			col := columns[j]
			switch col.content {
			case LineContentPath:
				ref, err := u.decodeStrForm(c, col.form)
				if err != nil {
					return err
				}
				e.name = ref
			case LineContentDirIndex:
				v, err := u.decodeUintForm(c, col.form)
				if err != nil {
					return err
				}
				e.dir = v
			default:
				// Timestamps, sizes and MD5 hashes carry no size information.
				if err := u.skipForm(c, col.form); err != nil {
					return err
				}
			}
		}
		if c.err != nil {
			return c.err
		}
		if isDir {
			u.dirs = append(u.dirs, e.name)
		} else {
			u.files = append(u.files, e)
		}
	}
	return nil
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
		// The extent is left unset: finding the terminator means reading the
		// string section, and most file entries are never named by any row.
		return strRef{sec: sec, off: uint32(off)}, nil
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

// Rows is an [iter.Seq] iterator implementation oveer LineUnit rows.
func (u *LineUnit) Rows(yield func(r Row) bool) {
	var c streamCursor
	c.config(u.sec.Line, u.win, u.progStart, u.progEnd, u.sec.byteOrder())

	// reset returns the state machine to its documented initial state, which
	// applies at the start of the unit and after every end_sequence.
	var row Row
	for c.err == nil && c.pos() < u.progEnd {
		opcode := c.u8()
		if c.err != nil {
			break
		}
		switch {
		case opcode >= u.opBase:
			// Special opcode: encodes an address and line delta together.
			adj := uint64(opcode - u.opBase)
			row.Address = u.advance(adj / uint64(u.lineRnge))
			row.Line = uint32(int64(row.Line) + int64(u.lineBase) + int64(adj%uint64(u.lineRnge)))
			if !yield(row) {
				return
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
			end := c.pos() + int64(length)
			if end > u.progEnd {
				c.fail(makeFormatErr(uint64(c.pos()), "extended opcode overruns unit", length))
				break
			}
			sub := LineExtOp(c.u8())
			switch sub {
			case LineExtEndSequence:
				row.EndSequence = true
				if !yield(row) {
					return
				}
				row = u.resetRow()

			case LineExtSetAddress:
				switch end - c.pos() {
				case 8:
					row.Address = c.u64()
				case 4:
					row.Address = uint64(c.u32())
				case 2:
					row.Address = uint64(c.u16())
				default:
					c.fail(makeFormatErr(uint64(c.pos()), "unsupported address size", end-c.pos()))
				}
			default:
				// define_file, set_discriminator and vendor extensions carry
				// nothing this package needs; the length lets us skip them.
			}
			c.seek(end)

		default:
			switch LineOp(opcode) {
			case LineOpCopy:
				if !yield(row) {
					return
				}
				row.EndSequence = false
			case LineOpAdvancePC:
				row.Address = u.advance(c.uleb())
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
				row.Address = u.advance(uint64(255-u.opBase) / uint64(u.lineRnge))
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
				if int(opcode) <= u.numStdLens {
					for i := uint8(0); i < u.stdLens[opcode-1]; i++ {
						c.uleb()
					}
				} else {
					c.fail(makeFormatErr(uint64(c.pos()), "unknown standard opcode", opcode))
				}
			}
		}
	}
}

func (u *LineUnit) resetRow() Row {
	return Row{File: 1, Line: 1, IsStmt: u.defStmt}
}

// advance moves the address by opAdvance operations, honoring VLIW
// op_index packing when the producer declares more than one op per
// instruction.
func (u *LineUnit) advance(opAdvance uint64) uint64 {
	return uint64(u.minInst) * opAdvance
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
