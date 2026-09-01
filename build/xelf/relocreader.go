package xelf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// relocField is one relocation reduced to the edit it makes: write size bytes
// at off, either replacing what is there or adding to it.
//
// Reducing to this form is what lets a relocation be applied to a section that
// is being read in pieces rather than held whole, since a patch no longer needs
// the surrounding bytes to be present to be described.
type relocField struct {
	off  uint64
	val  uint64
	size uint8
	add  bool // Add to the field's current value rather than replacing it.
}

// rangeRelocFields decodes a relocation section and calls fn with each field
// edit it describes, accumulating the reasons any entry was skipped. It is the
// single place that knows what each relocation type computes; both
// [ApplyRelocations] and [RelocReaderAt] drive it.
//
// It yields rather than returning a slice so the whole-buffer path stays
// allocation-free; a caller that needs the fields kept appends them itself.
//
// Bounds are deliberately not checked here: whether a field fits depends on the
// target, which a streaming reader does not have in one piece.
func rangeRelocFields(rels []byte, syms []Sym, hdr Header, fn func(relocField)) (RelocError, error) {
	if len(rels)%8 != 0 {
		return 0, errors.New("length of relocation section not multiple of 8")
	}
	if err := hdr.Data.Validate(); err != nil {
		return 0, err
	}
	bo := hdr.ByteOrder()
	var fail RelocError
	switch {
	case hdr.Class == Class32 && hdr.Machine == MachineARM:
		for len(rels) > 0 {
			rel, n, err := DecodeRel(rels, Class32, bo)
			if err != nil {
				return fail, err
			}
			rels = rels[n:]
			sym, ok := relocSym(rel.Info>>8, syms, &fail, false)
			if !ok {
				continue
			}
			switch RARM(rel.Info & 0xff) {
			case RARMABS32:
				// S + A, with the addend held in the field itself.
				fn(relocField{off: rel.Off, val: sym.Value, size: 4, add: true})
			default:
				fail |= relocUnhandledRelType
			}
		}
	case hdr.Class == Class64 && hdr.Machine == MachineX86_64:
		for len(rels) > 0 {
			rela, n, err := DecodeRela(rels, Class64, bo)
			if err != nil {
				return fail, err
			}
			rels = rels[n:]
			sym, ok := relocSym(rela.Info>>32, syms, &fail, true)
			if !ok {
				continue
			}
			// There are relocations, so this must be a normal object file. The
			// code below handles only basic relocations of the form S + A
			// (symbol plus addend).
			if rela.Addend < 0 {
				fail |= relocFailOOB
				continue
			}
			switch RX86_64(rela.Info & 0xffff) {
			case Rx86_6464:
				fn(relocField{off: rela.Off, val: sym.Value + uint64(rela.Addend), size: 8})
			case Rx86_6432:
				fn(relocField{off: rela.Off, val: uint64(uint32(sym.Value) + uint32(rela.Addend)), size: 4})
			default:
				fail |= relocUnhandledRelType
			}
		}
	case hdr.Class != Class32 && hdr.Class != Class64:
		return fail, errBadClass
	default:
		return fail, fmt.Errorf("relocation not implemented for tuple (%s, %s)", hdr.Class.String(), hdr.Machine.String())
	}
	return fail, nil
}

// relocSym resolves a relocation's symbol index. A zero index names no symbol
// and is skipped silently, the way an R_*_NONE entry should be.
func relocSym(symNo uint64, syms []Sym, fail *RelocError, checkApplicable bool) (Sym, bool) {
	if symNo == 0 {
		return Sym{}, false
	} else if symNo > uint64(len(syms)) {
		*fail |= relocFailOOBSymIdx
		return Sym{}, false
	}
	sym := syms[symNo-1]
	if checkApplicable && !canApplyRelocation(sym) {
		*fail |= relocFailUnableApply
		return Sym{}, false
	}
	return sym, true
}

// patch applies f to b, which holds the section bytes starting at base. A field
// straddling either end of b is not applied; [RelocReaderAt] handles that case
// by fetching the field whole.
func (f relocField) patch(b []byte, base uint64, bo binary.ByteOrder) bool {
	if f.off < base {
		return false
	}
	off := f.off - base
	if !fitsAt(b, off, uint64(f.size)) {
		return false
	}
	dst := b[off : off+uint64(f.size)]
	switch f.size {
	case 4:
		v := uint32(f.val)
		if f.add {
			v += bo.Uint32(dst)
		}
		bo.PutUint32(dst, v)
	case 8:
		v := f.val
		if f.add {
			v += bo.Uint64(dst)
		}
		bo.PutUint64(dst, v)
	}
	return true
}

// RelocReaderAt reads a section through its relocations, applying each fixup to
// the bytes as they are handed back. It exists so DWARF in a relocatable object
// -- TinyGo emits .rel.debug_* -- can be read in pieces: applying relocations in
// place, the way [ApplyRelocations] does, requires the whole section resident,
// which is the cost a windowed reader is there to avoid.
//
// The zero value is unusable; see [RelocReaderAt.Reset].
type RelocReaderAt struct {
	r      io.ReaderAt
	fields []relocField // Sorted by offset.
	bo     binary.ByteOrder
	fail   RelocError
}

// Reset binds rr to the body of section sec within f, decoding the relocations
// that target it. It reports whether any were; when none were, rr is left bound
// to sec's bytes unchanged, so a caller can use it either way without branching.
//
// Only a relocatable object is relocated. A linked file's sections already hold
// final addresses, and applying its relocations again would add each symbol's
// value a second time -- which stays invisible while the target section sits at
// address zero and corrupts every address once it does not. Such a file may
// still carry relocation sections: TinyGo's executables keep .rel.debug_*, and
// the values there describe a link that already happened. debug/elf declines
// them for the same reason.
//
// Relocation types this build does not implement leave those particular fields
// alone, which [RelocReaderAt.Err] reports; the rest of the section is still
// usable, and an unresolved address simply fails to match a symbol.
func (rr *RelocReaderAt) Reset(f *File, sec FileSection) (relocated bool, err error) {
	rr.r, rr.fields, rr.fail = sec.Open(), rr.fields[:0], 0
	hdr := f.Header()
	rr.bo = hdr.ByteOrder()
	if hdr.Type != TypeRelocatable {
		return false, nil
	}
	rels, ok := f.RelocationsFor(sec.Index())
	if !ok {
		return false, nil
	}
	relData, err := rels.AppendData(nil)
	if err != nil {
		return false, err
	}
	syms, err := f.AppendTableSymbols(nil)
	if err != nil {
		return false, err
	}
	rr.fail, err = rangeRelocFields(relData, syms, hdr, func(f relocField) {
		rr.fields = append(rr.fields, f)
	})
	if err != nil {
		return false, err
	}
	// ReadAt binary-searches for the first field that could touch a span, so the
	// table has to be ordered even though a producer's usually already is.
	sort.Slice(rr.fields, func(i, j int) bool { return rr.fields[i].off < rr.fields[j].off })
	return len(rr.fields) > 0, nil
}

// Err reports why some relocations were not applied, or nil if all were.
func (rr *RelocReaderAt) Err() error {
	if rr.fail == 0 {
		return nil
	}
	return rr.fail
}

// ReadAt implements [io.ReaderAt] over the relocated section.
func (rr *RelocReaderAt) ReadAt(b []byte, off int64) (int, error) {
	n, err := rr.r.ReadAt(b, off)
	if n <= 0 || len(rr.fields) == 0 || off < 0 {
		return n, err
	}
	base, end := uint64(off), uint64(off)+uint64(n)
	// The first field that can reach into [base, end) may start before it, by up
	// to one field width; back the search up by the widest field so a straddler
	// is not missed.
	const maxField = 8
	from := base
	if from > maxField {
		from -= maxField
	} else {
		from = 0
	}
	i := sort.Search(len(rr.fields), func(i int) bool { return rr.fields[i].off >= from })
	for ; i < len(rr.fields) && rr.fields[i].off < end; i++ {
		f := rr.fields[i]
		if f.patch(b[:n], base, rr.bo) {
			continue
		}
		if f.off+uint64(f.size) <= base {
			continue // Entirely behind the span; the backed-up search overshot.
		}
		// The field crosses an edge of b, so the bytes needed to compute it are
		// not all here. Fetch it whole and copy back only the overlap.
		if err := rr.patchStraddling(b[:n], base, f); err != nil {
			return n, err
		}
	}
	return n, err
}

// patchStraddling applies a field that hangs off an edge of b, by reading the
// field's own bytes from the underlying section. An add-form relocation needs
// every byte of the original to compute its result, so the partial copy in b
// cannot be patched in place.
func (rr *RelocReaderAt) patchStraddling(b []byte, base uint64, f relocField) error {
	var field [8]byte
	fb := field[:f.size]
	if _, err := rr.r.ReadAt(fb, int64(f.off)); err != nil && err != io.EOF {
		return err
	}
	f.patch(fb, f.off, rr.bo)
	// Copy back whatever part of the field b actually covers.
	lo, hi := f.off, f.off+uint64(f.size)
	if lo < base {
		lo = base
	}
	if end := base + uint64(len(b)); hi > end {
		hi = end
	}
	if lo >= hi {
		return nil
	}
	copy(b[lo-base:hi-base], fb[lo-f.off:hi-f.off])
	return nil
}
