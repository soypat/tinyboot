package xobj

import (
	"github.com/soypat/tinyboot/build"
	"github.com/soypat/tinyboot/build/xelf"
	"github.com/soypat/tinyboot/build/xwasm"
)

// Symbol is a named range of a section: a function or a data object. Its name
// is read on request: [File.SymbolNameLen] sizes a buffer,
// [File.ReadSymbolName] fills it, for as long as f describes the binary the
// symbol came from.
type Symbol struct {
	// Index is the symbol's index in its format's own numbering: its ELF symbol
	// table index, or a WebAssembly function's index in the function index
	// space (imports first) or data segment's index.
	Index int
	// Section is the [Section.Index] of the section the symbol lies in.
	Section int
	// Off and Size locate the symbol within its section. A WebAssembly
	// function's range covers its body's size prefix, and a segment's its
	// header, so that between them they tile the section.
	Off, Size uint64
	Func      bool // A function rather than a data object.

	// name locates the name: an ELF string table offset, or a WebAssembly
	// name map entry.
	name xwasm.NameEntry
}

// Symbols yields the binary's functions and data objects. ELF symbols come in
// symbol table order, limited to FUNC and OBJECT symbols in a real section. A
// WebAssembly module yields every function body in order of index, then every
// data segment, whether or not its name section names them. [File.Err]
// reports why a walk stopped early.
func (f *File) Symbols(yield func(Symbol) bool) {
	f.err = nil
	switch f.format {
	case FormatELF:
		f.err = f.elfSymbols(yield)
	case FormatWasm:
		f.err = f.wasmSymbols(yield)
	default:
		f.err = build.ErrNotRead
	}
}

// SymbolNameLen returns the length of sym's name: zero for a WebAssembly
// function or segment the name section does not name.
func (f *File) SymbolNameLen(sym Symbol) (int, error) {
	switch f.format {
	case FormatELF:
		return f.syms.NameLen(xelf.Sym{Name: uint32(sym.name.Off)})
	case FormatWasm:
		return int(sym.name.Len), nil
	}
	return 0, build.ErrNotRead
}

// ReadSymbolName reads sym's name into dst, which [File.SymbolNameLen] sizes,
// and returns its length. A dst too short for the name fails with
// [io.ErrShortBuffer].
func (f *File) ReadSymbolName(dst []byte, sym Symbol) (int, error) {
	switch f.format {
	case FormatELF:
		return f.syms.ReadName(dst, xelf.Sym{Name: uint32(sym.name.Off)})
	case FormatWasm:
		if sym.name.Len == 0 {
			return 0, nil
		}
		return f.names.ReadName(dst, sym.name)
	}
	return 0, build.ErrNotRead
}

func (f *File) elfSymbols(yield func(Symbol) bool) error {
	sr := &f.syms
	if err := sr.Reset(&f.elf, f.win[0][:]); err != nil {
		return err
	}
	nsect := f.elf.NumSections()
	thumb := f.elf.Header().Machine == xelf.MachineARM
	for sym, ok := sr.Next(); ok; sym, ok = sr.Next() {
		typ := xelf.SymType(sym.Info & 0xf)
		if typ != xelf.SymTypeFunc && typ != xelf.SymTypeObject {
			continue
		}
		idx := int(sym.Shndx)
		// SHN_ABS, SHN_COMMON and friends do not name a real section.
		if idx <= 0 || idx >= nsect || xelf.SectionIndex(sym.Shndx) >= xelf.SecIdxReserveLo {
			continue
		}
		if thumb && typ == xelf.SymTypeFunc {
			// The ARM ELF ABI marks a Thumb function by setting bit 0 of its
			// value; its first instruction is at the value with that bit clear.
			sym.Value &^= 1
		}
		sec, err := f.elf.Section(idx)
		if err != nil {
			return err
		}
		if !yield(Symbol{
			Index:   sr.Index(),
			Section: idx,
			// A relocatable object's sections all sit at address zero, where
			// this leaves the symbol value as it is.
			Off:  sym.Value - sec.SectionHeader().Addr,
			Size: sym.Size,
			Func: typ == xelf.SymTypeFunc,
			name: xwasm.NameEntry{Off: uint64(sym.Name)},
		}) {
			return nil
		}
	}
	return sr.Err()
}

// wasmSymbols merge-joins the Code section's bodies with the function name map,
// then the Data section's segments with the data name map. Both sides of each
// join ascend by index, so the walk holds one entry of each at a time.
func (f *File) wasmSymbols(yield func(Symbol) bool) error {
	if err := f.code.Reset(&f.wasm, f.win[0][:]); err != nil {
		return err
	}
	if err := f.data.Reset(&f.wasm, f.win[1][:]); err != nil {
		return err
	}
	if err := f.names.Reset(&f.wasm, f.win[2][:]); err != nil {
		return err
	}
	code, data := -1, -1
	for i := 0; i < f.wasm.NumSections(); i++ {
		s, _ := f.wasm.Section(i)
		switch s.SectionHeader().ID {
		case xwasm.SecCode:
			code = i
		case xwasm.SecData:
			data = i
		}
	}

	f.names.Open(xwasm.NameMapFuncs)
	j := joiner{nr: &f.names}
	j.advance()
	for fn, ok := f.code.Next(); ok; fn, ok = f.code.Next() {
		if !yield(Symbol{
			Index:   int(fn.Index),
			Section: code,
			Off:     fn.Offset,
			Size:    fn.End() - fn.Offset,
			Func:    true,
			name:    j.nameOf(fn.Index),
		}) {
			return nil
		}
	}
	if err := j.finish(f.code.Err()); err != nil {
		return err
	}

	f.names.Open(xwasm.NameMapData)
	j.advance()
	for seg, ok := f.data.Next(); ok; seg, ok = f.data.Next() {
		if !yield(Symbol{
			Index:   int(seg.Index),
			Section: data,
			Off:     seg.Offset,
			Size:    seg.End() - seg.Offset,
			name:    j.nameOf(seg.Index),
		}) {
			return nil
		}
	}
	return j.finish(f.data.Err())
}

// joiner walks one name map alongside the items it names.
type joiner struct {
	nr *xwasm.NameReader
	e  xwasm.NameEntry
	ok bool
}

func (j *joiner) advance() { j.e, j.ok = j.nr.Next() }

// nameOf returns the name entry of item idx, or a zero entry if the map names
// none. Items must be asked for in increasing order of index.
func (j *joiner) nameOf(idx uint32) xwasm.NameEntry {
	for j.ok && j.e.Index < idx {
		j.advance() // Named, but not an item of ours: an imported function.
	}
	if j.ok && j.e.Index == idx {
		return j.e
	}
	return xwasm.NameEntry{}
}

// finish drains the map, so that a malformed entry past the last item is still
// caught, and reports the first failure of the items' walk or the map's.
func (j *joiner) finish(walkErr error) error {
	if walkErr != nil {
		return walkErr
	}
	for j.ok {
		j.advance()
	}
	return j.nr.Err()
}
