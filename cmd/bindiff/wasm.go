package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xwasm"
)

var errWasmNoDebugLine = errors.New("WebAssembly module has no .debug_line section")

// isWasm reports whether r holds a WebAssembly module rather than an ELF.
func isWasm(r io.ReaderAt) bool {
	var magic [4]byte
	n, _ := r.ReadAt(magic[:], 0)
	return n == len(magic) && string(magic[:]) == "\x00asm"
}

// profileWasm is profileReader for a WebAssembly module.
//
// A module has no segments and no load addresses: its code runs from the Code
// section and its linear memory is sized at run time. The segment kind and
// memory mode have no counterpart, and report so rather than guess.
func profileWasm(r io.ReaderAt, size int64, flags Flags) ([]Entry, error) {
	var f xwasm.File
	if err := f.Read(r); err != nil {
		return nil, err
	}
	if flags.mem {
		return nil, errors.New("-mem is not supported for WebAssembly: linear memory is sized at run time")
	}
	switch flags.kind {
	case KindSection:
		return profileWasmSections(&f, size)
	case KindSymbol, KindPackage, KindFile, KindLine:
	default:
		return nil, fmt.Errorf("granularity %q does not apply to WebAssembly", flags.kind)
	}
	t, err := tileWasm(&f)
	if err != nil {
		return nil, err
	}
	switch flags.kind {
	case KindSymbol:
		return symbolEntries(t), nil
	case KindPackage:
		return packageEntries(symbolEntries(t)), nil
	}
	idx, err := loadWasmLineIndex(&f)
	if err != nil {
		return nil, err
	}
	return attributeSource(t, idx, flags.kind == KindLine), nil
}

// profileWasmSections attributes a module's bytes to its sections, custom ones
// by their own name. The entries sum exactly to the size of the file: each
// section's framing -- id, size and a custom section's name -- is collected,
// with the module header, under [wasm-headers].
func profileWasmSections(f *xwasm.File, fileSize int64) ([]Entry, error) {
	nsect := f.NumSections()
	entries := make([]Entry, 0, nsect+2)
	overhead := int64(f.Header().HeaderSize())
	covered := overhead
	var name []byte
	for i := 0; i < nsect; i++ {
		s, err := f.Section(i)
		if err != nil {
			return nil, err
		}
		sh := s.SectionHeader()
		name, err = s.AppendName(name[:0])
		if err != nil {
			return nil, fmt.Errorf("section %d name: %w", i, err)
		}
		entries = append(entries, Entry{Kind: KindSection, Name: string(name), New: int64(sh.Size)})
		overhead += int64(sh.FrameSize())
		covered += int64(sh.FrameSize() + sh.Size)
	}
	entries = append(entries, Entry{Kind: KindSection, Name: "[wasm-headers]", New: overhead})
	// Sections tile a module exactly, so this only fires for trailing bytes
	// xwasm would have rejected; it is kept so the total cannot silently lie.
	if rem := fileSize - covered; rem != 0 {
		entries = append(entries, Entry{Kind: KindSection, Name: Unattributed, New: rem})
	}
	return entries, nil
}

// tileWasm divides a module's sections among its functions and data segments.
// Every other section has no symbols and goes wholly to its remainder, as a
// symbol-less ELF section does.
//
// Code placements are Code section offsets and cover a body with its size
// prefix, so only the section's leading function count is left unattributed.
// That is the address space DWARF uses, so the line table can be laid over
// them directly.
func tileWasm(f *xwasm.File) (tiling, error) {
	funcNames, err := readNameMap(f, (*xwasm.NameReader).FuncNames)
	if err != nil {
		return tiling{}, fmt.Errorf("function names: %w", err)
	}
	dataNames, err := readNameMap(f, (*xwasm.NameReader).DataNames)
	if err != nil {
		return tiling{}, fmt.Errorf("data segment names: %w", err)
	}
	var cr xwasm.CodeReader
	var dr xwasm.DataReader
	// Each reader owns its window; sharing one would let either walk clobber
	// the bytes the other believes resident.
	var cbuf, dbuf [512]byte
	if err := cr.Reset(f, cbuf[:]); err != nil {
		return tiling{}, err
	}
	if err := dr.Reset(f, dbuf[:]); err != nil {
		return tiling{}, err
	}

	nsect := f.NumSections()
	t := newTiling(nsect, int(cr.NumFuncs())+int(dr.NumSegments()))
	t.lineSection = xwasm.SecCode.String()
	var nameBuf []byte
	var claims []claim
	for i := 0; i < nsect; i++ {
		s, err := f.Section(i)
		if err != nil {
			return t, err
		}
		sh := s.SectionHeader()
		nameBuf, err = s.AppendName(nameBuf[:0])
		if err != nil {
			return t, err
		}
		claims = claims[:0]
		switch sh.ID {
		case xwasm.SecCode:
			for fn := range cr.Funcs {
				claims = append(claims, claim{
					name:  nameOr(funcNames, fn.Index, "func"),
					start: fn.Offset,
					size:  fn.End() - fn.Offset,
				})
			}
			err = cr.Err()
		case xwasm.SecData:
			for seg := range dr.Segments {
				claims = append(claims, claim{
					name:  nameOr(dataNames, seg.Index, "data"),
					start: seg.Offset,
					size:  seg.End() - seg.Offset,
				})
			}
			err = dr.Err()
		}
		if err != nil {
			return t, fmt.Errorf("%s section: %w", sh.ID, err)
		}
		t.tileSection(string(nameBuf), int64(sh.Size), claims)
	}
	return t, nil
}

// nameOr returns the name the name section gives index, or a placeholder
// naming the index space when it gives none.
func nameOr(names map[uint32]string, index uint32, space string) string {
	if name, ok := names[index]; ok {
		return name
	}
	return fmt.Sprintf("%s[%d]", space, index)
}

// readNameMap collects one of the name section's maps, growing the read
// buffer until it holds the longest name. A module without a name section
// yields an empty map.
func readNameMap(f *xwasm.File, walk func(*xwasm.NameReader, func(uint32, []byte) bool)) (map[uint32]string, error) {
	buf := make([]byte, 256)
	for {
		var nr xwasm.NameReader
		if err := nr.Reset(f, buf); err != nil {
			return nil, err
		}
		names := make(map[uint32]string)
		walk(&nr, func(idx uint32, name []byte) bool {
			names[idx] = string(name)
			return true
		})
		var small xwasm.BufferTooSmallError
		if errors.As(nr.Err(), &small) {
			buf = make([]byte, small.Need)
			continue
		}
		return names, nr.Err()
	}
}

// loadWasmLineIndex builds the line index from a module's DWARF custom
// sections. They are stored uncompressed and, in a linked module, already
// relocated, so unlike an ELF they are read in place with no preparation.
func loadWasmLineIndex(f *xwasm.File) (*lineIndex, error) {
	line, err := f.SectionByName(".debug_line")
	if err != nil {
		return nil, errWasmNoDebugLine
	}
	sec := xdwarf.Sections{Line: line.Open(), ByteOrder: binary.LittleEndian}
	if s, err := f.SectionByName(".debug_str"); err == nil {
		sec.Str = s.Open()
	}
	if s, err := f.SectionByName(".debug_line_str"); err == nil {
		sec.LineStr = s.Open()
	}
	aux := make([]byte, defaultAux)
	for {
		idx, err := buildLineIndex(sec, line.Size(), aux)
		var small xdwarf.AuxTooSmallError
		if errors.As(err, &small) {
			aux = make([]byte, small.Need)
			continue
		}
		return idx, err
	}
}
