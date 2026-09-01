package xelf

import (
	"errors"
	"fmt"
)

// RelocError is returned by [ApplyRelocations] when a [Rel] or [Rela] is unable to be applied to
// the target program.
type RelocError int

const (
	relocFailOOB RelocError = 1 << iota
	relocUnhandledRelType
	relocFailUnableApply
	relocFailOOBSymIdx
)

func (fail RelocError) IsOOB() bool              { return fail&relocFailOOB != 0 }
func (fail RelocError) IsUnhandledRelType() bool { return fail&relocUnhandledRelType != 0 }
func (fail RelocError) IsUnableToApply() bool    { return fail&relocFailUnableApply != 0 }
func (fail RelocError) IsBadSymIdx() bool        { return fail&relocFailOOBSymIdx != 0 }

func (fail RelocError) Error() (s string) {
	if fail.IsOOB() {
		s += "reloc OOB|"
	}
	if fail.IsUnhandledRelType() {
		s += "unknown reloc type|"
	}
	if fail.IsUnableToApply() {
		s += "unnable apply reloc|"
	}
	if fail.IsBadSymIdx() {
		s += "incomplete symbol table or OOB symidx|"
	}
	if len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// ApplyRelocations applies relocations to dst. rels is a relocations section. syms is the symbol table.
func ApplyRelocations(dst []byte, rels []byte, syms []Sym, hdr Header) (err error) {
	if len(rels) == 0 {
		return errors.New("empty relocation data")
	} else if len(syms) == 0 {
		return errors.New("no symbols for relocation")
	}
	bo := hdr.ByteOrder()
	var oob RelocError
	fail, err := rangeRelocFields(rels, syms, hdr, func(f relocField) {
		// dst is the whole section here, so a field that does not fit is out of
		// bounds rather than merely out of view.
		if !f.patch(dst, 0, bo) {
			oob |= relocFailOOB
		}
	})
	if err != nil {
		return err
	}
	if fail |= oob; fail != 0 {
		return fail
	}
	return nil
}

// canApplyRelocation reports whether we should try to apply a
// relocation to a DWARF data section, given a pointer to the symbol
// targeted by the relocation.
// Most relocations in DWARF data tend to be section-relative, but
// some target non-section symbols (for example, low_PC attrs on
// subprogram or compilation unit DIEs that target function symbols).
func canApplyRelocation(sym Sym) bool {
	sec := SectionIndex(sym.Shndx)
	return sec != SecIdxUndef && sec < SecIdxReserveLo
}

// RelocationsFor returns the relocation section targeting the section at index
// target, reporting whether one was found.
//
// ELF links a relocation section to the section it modifies through sh_info.
// Honoring that link matters: applying an unrelated section's relocations (say
// .rela.dyn, which targets .got and .data) onto .debug_info silently corrupts
// the target rather than failing.
func (f *File) RelocationsFor(target int) (FileSection, bool) {
	nsect := f.NumSections()
	for i := 0; i < nsect; i++ {
		s, err := f.Section(i)
		if err != nil {
			return FileSection{}, false
		}
		sh := s.SectionHeader()
		if sh.Type != SecTypeRel && sh.Type != SecTypeRelA {
			continue
		}
		if int(sh.Info) == target {
			return s, true
		}
	}
	return FileSection{}, false
}

// fitsAt reports whether a size-byte field starting at off lies entirely within b.
// Phrased to avoid overflowing off+size, since off comes from an untrusted file.
func fitsAt(b []byte, off, size uint64) bool {
	return uint64(len(b)) >= size && off <= uint64(len(b))-size
}

// AppendTableSymbols appends the symbol table entities to the argument buffer and returns the result.
// It performs no I/O on the symbol name strings, which can be obtained by calling [File.AppendSymStr].
//
//	str, err := f.AppendSymStr(nil, sym.Name)
func (f *File) AppendTableSymbols(dst []Sym) ([]Sym, error) {
	return f.appendSymbols(dst, SecTypeSymTab)
}

func (f *File) appendSymbols(dst []Sym, typ SectionType) ([]Sym, error) {
	class := f.hdr.Class
	symtabSection, err := f.SectionByType(typ)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoSymbols, err)
	}
	symtabSh := symtabSection.SectionHeader()
	data, err := symtabSection.AppendData(nil)
	symSize := symSize32
	if class == Class64 {
		symSize = symSize64
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load symbol section: %w", err)
	} else if len(data) == 0 {
		return nil, errors.New("empty symbol section")
	} else if (class == Class32 && len(data)%symSize32 != 0) || (class == Class64 && len(data)%symSize64 != 0) {
		return nil, errors.New("length of symbol section is not a multiple of SymSize")
	} else if symtabSh.Entsize != uint64(symSize) {
		return nil, makeFormatErr(symtabSh.Offset, "entsize not match symbol size", symtabSh.Entsize)
	}
	bo := f.hdr.ByteOrder()

	// Skip over first entry, is all zeros.
	_, n, err := DecodeSym(data, class, bo)
	if err != nil {
		return nil, err
	}
	data = data[n:]

	for len(data) > 0 {
		sym, n, err := DecodeSym(data, class, bo)
		if err != nil {
			return dst, err
		}
		dst = append(dst, sym)
		data = data[n:]
	}
	return dst, nil
}
