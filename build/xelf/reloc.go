package xelf

import (
	"encoding/binary"
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
	class := hdr.Class
	machine := hdr.Machine
	err = hdr.Data.Validate()
	if err != nil {
		return err
	}
	bo := hdr.ByteOrder()
	switch class {
	case Class32:
		switch machine {
		case MachineARM:
			err = applyRelocationsARM(dst, rels, syms, bo)
		default:
			err = fmt.Errorf("relocation not implemented for tuple (Class32, %s)", machine.String())
		}
	case Class64:
		switch machine {
		case MachineX86_64:
			err = applyRelocationsAMD64(dst, rels, syms, bo)
		default:
			err = fmt.Errorf("relocation not implemented for tuple (Class64, %s)", machine.String())
		}
	default:
		err = errBadClass
	}
	return err
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

func applyRelocationsARM(dst []byte, rels []byte, syms []Sym, bo binary.ByteOrder) (err error) {
	if len(rels)%8 != 0 {
		return errors.New("length of relocation section not multiple of 8")
	}
	var fail RelocError
	for len(rels) > 0 {
		rel, n, err := DecodeRel(rels, Class32, bo)
		if err != nil {
			return err
		}
		rels = rels[n:]
		symNo := rel.Info >> 8
		t := RARM(rel.Info & 0xff)
		if symNo == 0 {
			continue
		} else if symNo > uint64(len(syms)) {
			fail |= relocFailOOBSymIdx
			continue
		}
		sym := &syms[symNo-1]
		switch t {
		case RARMABS32:
			if rel.Off+4 >= uint64(len(dst)) {
				fail |= relocFailOOB
				continue
			}
			val := bo.Uint32(dst[rel.Off : rel.Off+4])
			val += uint32(sym.Value)
			bo.PutUint32(dst[rel.Off:rel.Off+4], val)
		default:
			fail |= relocUnhandledRelType
		}
	}
	if fail != 0 {
		return fail
	}
	return nil
}

func applyRelocationsAMD64(dst []byte, relas []byte, syms []Sym, bo binary.ByteOrder) (err error) {
	if len(relas)%8 != 0 {
		return errors.New("length of relocation section not multiple of 8")
	}
	var fail RelocError
	for len(relas) > 0 {
		rela, n, err := DecodeRela(relas, Class64, bo)
		if err != nil {
			return err
		}
		relas = relas[n:]
		symNo := rela.Info >> 32
		t := RX86_64(rela.Info & 0xffff)
		if symNo == 0 {
			continue
		} else if symNo > uint64(len(syms)) {
			fail |= relocFailOOBSymIdx
			continue
		}
		sym := &syms[symNo-1]
		if !canApplyRelocation(*sym) {
			fail |= relocFailUnableApply
			continue
		}

		// There are relocations, so this must be a normal
		// object file.  The code below handles only basic relocations
		// of the form S + A (symbol plus addend).
		switch t {
		case Rx86_6464:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				fail |= relocFailOOB
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			bo.PutUint64(dst[rela.Off:rela.Off+8], val64)

		case Rx86_6432:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				fail |= relocFailOOB
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			bo.PutUint32(dst[rela.Off:rela.Off+4], val32)

		default:
			fail |= relocUnhandledRelType
		}
	}
	if fail != 0 {
		return fail
	}
	return nil
}

func (f *File) AppendTableSymbols(dst []Sym) ([]Sym, error) {
	return f.appendSymbols(dst, SecTypeSymTab)
}

func (f *File) appendSymbols(dst []Sym, typ SectionType) ([]Sym, error) {
	class := f.hdr.Class
	symtabSection, err := f.SectionByType(typ)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoSymbols, err)
	}
	data, err := symtabSection.AppendData(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load symbol section: %w", err)
	} else if len(data) == 0 {
		return nil, errors.New("empty symbol section")
	} else if (class == Class32 && len(data)%symSize32 != 0) || (class == Class64 && len(data)%symSize64 != 0) {
		return nil, errors.New("length of symbol section is not a multiple of SymSize")
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
