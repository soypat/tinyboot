package xelf

import (
	"io"

	"github.com/soypat/tinyboot/build"
)

// SymReader walks a binary's symbol table through a caller-owned window,
// holding one window of entries at a time. Unlike [File.AppendTableSymbols] it
// never materializes the table, so a walk allocates nothing however many
// symbols the binary has. Names are read on request into the caller's buffer:
// [SymReader.NameLen] sizes it, [SymReader.ReadName] fills it.
//
// A SymReader is reusable: [SymReader.Reset] points it at another binary and
// keeps the window. The window belongs to the reader from Reset until the next
// Reset.
type SymReader struct {
	f        *File
	tab, str FileSection
	win      []byte
	pending  []byte // Entries read into win but not yet decoded.
	entsize  int
	count    int // Entries in the table, the leading null entry included.
	next     int // Table index of the entry Next decodes.
	done     bool
	err      error
}

// Reset points sr at f's SHT_SYMTAB symbol table and rewinds it to the first
// symbol after the null entry. Entries are read through win, which must hold at
// least one, 24 bytes for a 64-bit binary; a shorter win fails with
// [io.ErrShortBuffer]. More means fewer reads. A binary without a symbol table
// yields no symbols.
func (sr *SymReader) Reset(f *File, win []byte) error {
	*sr = SymReader{f: f, win: win, done: true}
	tab, err := f.SectionByType(SecTypeSymTab)
	if err != nil {
		return nil // No symbol table: nothing to walk.
	}
	sh := tab.SectionHeader()
	sr.entsize = symSize32
	if f.hdr.Class == Class64 {
		sr.entsize = symSize64
	}
	if sh.Entsize != uint64(sr.entsize) {
		return build.ErrBadEntsize
	} else if sh.SizeOnFile%uint64(sr.entsize) != 0 {
		return build.ErrTableNotMultiple
	} else if len(win) < sr.entsize {
		return io.ErrShortBuffer
	}
	str, err := f.Section(int(sh.Link))
	if err != nil || str.SectionHeader().Type != SecTypeStrTab {
		return build.ErrBadLink
	}
	sr.tab, sr.str = tab, str
	sr.count = int(sh.SizeOnFile / uint64(sr.entsize))
	sr.Rewind()
	return nil
}

// NumSymbols returns the number of entries in the symbol table, the leading
// null entry included, as symbol indices count them.
func (sr *SymReader) NumSymbols() int { return sr.count }

// Err returns why the walk stopped early, or nil if it ran to completion or the
// caller stopped it.
func (sr *SymReader) Err() error { return sr.err }

// Rewind positions sr before the first symbol after the null entry, to walk the
// table anew.
func (sr *SymReader) Rewind() {
	sr.next, sr.pending, sr.err = 1, nil, nil
	sr.done = sr.count <= 1
}

// Index returns the symbol table index of the symbol Next last returned.
func (sr *SymReader) Index() int { return sr.next - 1 }

// Next returns the next symbol in table order. It reports false once the
// symbols run out or the walk fails; [SymReader.Err] tells which.
func (sr *SymReader) Next() (Sym, bool) {
	if sr.done {
		return Sym{}, false
	}
	if sr.next == sr.count {
		sr.done = true
		return Sym{}, false
	}
	if len(sr.pending) < sr.entsize {
		n := min(len(sr.win)/sr.entsize, sr.count-sr.next) * sr.entsize
		b, err := sr.tab.readAt(sr.win[:n], int64(sr.next*sr.entsize))
		if err == nil && len(b) != n {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return sr.fail(err)
		}
		sr.pending = b
	}
	sym, _, err := DecodeSym(sr.pending, sr.f.hdr.Class, sr.f.hdr.ByteOrder())
	if err != nil {
		return sr.fail(err)
	}
	sr.pending = sr.pending[sr.entsize:]
	sr.next++
	return sym, true
}

func (sr *SymReader) fail(err error) (Sym, bool) {
	sr.done, sr.err = true, err
	return Sym{}, false
}

// NameLen returns the length of sym's name in the table's string table.
func (sr *SymReader) NameLen(sym Sym) (int, error) {
	if sym.Name == 0 {
		return 0, nil // Index zero is the empty string.
	}
	return sr.str.strLen(int64(sym.Name))
}

// ReadName reads sym's name into dst, which [SymReader.NameLen] sizes, and
// returns its length. A dst too short for the name fails with
// [io.ErrShortBuffer].
func (sr *SymReader) ReadName(dst []byte, sym Sym) (int, error) {
	if sym.Name == 0 {
		return 0, nil
	}
	name, err := sr.str.appendStr(dst[:0:len(dst)], int64(sym.Name), false)
	return len(name), err
}
