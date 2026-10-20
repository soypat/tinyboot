package main

import (
	"fmt"

	"github.com/soypat/tinyboot/build/xelf"
	"github.com/soypat/tinyboot/build/xobj"
)

// xelf keeps its prog flag constants unexported, so the values this package
// needs are restated here.
const (
	progFlagX xelf.ProgFlag = 0x1 // PF_X
	progFlagW xelf.ProgFlag = 0x2 // PF_W
	progFlagR xelf.ProgFlag = 0x4 // PF_R
)

// progPerms renders segment permissions as an ls-style rwx triad.
func progPerms(f xelf.ProgFlag) string {
	perms := []byte("---")
	if f&progFlagR != 0 {
		perms[0] = 'r'
	}
	if f&progFlagW != 0 {
		perms[1] = 'w'
	}
	if f&progFlagX != 0 {
		perms[2] = 'x'
	}
	return string(perms)
}

// profileSections attributes bytes to sections.
//
// In file mode the entries sum exactly to the size of the file: sections that
// occupy no file bytes (SHT_NOBITS, i.e. .bss) contribute zero, and the
// format's structure -- ELF's header and header tables, a WebAssembly module's
// preamble and section framing -- is collected under [elf-headers] or
// [wasm-headers]. Whatever is left is padding between sections, or bytes no
// section claims. In memory mode only loaded sections count, and .bss
// contributes its run-time size.
func profileSections(f *xobj.File, fileSize int64, mem bool) ([]Entry, error) {
	entries := make([]Entry, 0, f.NumSections()+2)

	// covered tracks file bytes claimed by something, to derive the remainder.
	covered := int64(0)
	var names nameBuf
	for s := range f.Sections {
		var size int64
		if mem {
			if !s.Loaded {
				continue // Not resident: debug info, symbol tables, comments.
			}
			size = int64(s.MemSize)
		} else {
			size = int64(s.Size)
			covered += size
		}
		name, err := names.section(f, s.Index)
		if err != nil {
			return nil, err
		}
		entries = append(entries, Entry{
			Kind: KindSection,
			Name: name,
			Pos:  Pos{Addr: s.Addr},
			New:  size,
		})
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	if mem {
		return entries, nil
	}

	overhead := f.HeaderBytes()
	entries = append(entries, Entry{Kind: KindSection, Name: "[" + f.Format().String() + "-headers]", New: overhead})
	covered += overhead

	// Reporting the remainder keeps the total honest.
	if rem := fileSize - covered; rem != 0 {
		entries = append(entries, Entry{Kind: KindSection, Name: Unattributed, New: rem})
	}
	return entries, nil
}

// profileSegments attributes bytes to PT_LOAD program headers, the view the
// loader actually acts on. In memory mode a segment's Memsz exceeding its file
// size is the .bss contribution, which costs RAM but no flash.
func profileSegments(f *xelf.File, mem bool) ([]Entry, error) {
	nprog := f.NumProgs()
	entries := make([]Entry, 0, nprog)
	for i := 0; i < nprog; i++ {
		p, err := f.Prog(i)
		if err != nil {
			return nil, fmt.Errorf("prog %d: %w", i, err)
		}
		ph := p.ProgHeader()
		if ph.Type != xelf.ProgTypeLoad {
			continue
		}
		size := int64(ph.SizeOnFile)
		if mem {
			size = int64(ph.Memsz)
		}
		entries = append(entries, Entry{
			Kind: KindSegment,
			Name: fmt.Sprintf("LOAD[%d] %s", i, progPerms(ph.Flags)),
			Pos:  Pos{Addr: ph.Vaddr},
			New:  size,
		})
	}
	return entries, nil
}
