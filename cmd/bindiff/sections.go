package main

import (
	"fmt"

	"github.com/soypat/tinyboot/build/xelf"
)

// xelf keeps its section and prog flag constants unexported, so the values this
// package needs are restated here.
const (
	secFlagAlloc xelf.SectionFlag = 0x2 // SHF_ALLOC: occupies memory at run time.

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

// profileSections attributes bytes to ELF sections.
//
// In file mode the entries sum exactly to the size of the file: sections that
// occupy no file bytes (SHT_NOBITS, i.e. .bss) contribute zero, and the ELF
// header, program header table, section header table and any inter-section
// padding are accounted for explicitly. In memory mode only allocated sections
// count, and .bss contributes its run-time size.
func profileSections(f *xelf.File, fileSize int64, mem bool) ([]Entry, error) {
	hdr := f.Header()
	nsect := f.NumSections()
	entries := make([]Entry, 0, nsect+2)

	// covered tracks file bytes claimed by something, to derive the remainder.
	covered := int64(0)
	var name []byte
	for i := 0; i < nsect; i++ {
		s, err := f.Section(i)
		if err != nil {
			return nil, fmt.Errorf("section %d: %w", i, err)
		}
		sh := s.SectionHeader()
		if sh.Type == xelf.SecTypeNull {
			continue
		}
		name, err = s.AppendName(name[:0])
		if err != nil {
			return nil, fmt.Errorf("section %d name: %w", i, err)
		}

		var size int64
		if mem {
			if sh.Flags&secFlagAlloc == 0 {
				continue // Not resident: debug info, symbol tables, comments.
			}
			size = int64(sh.SizeOnFile) // sh_size is the memory size for NOBITS.
		} else {
			if sh.Type == xelf.SecTypeNobits {
				size = 0 // Occupies address space, not file bytes.
			} else {
				size = int64(sh.SizeOnFile)
			}
			covered += size
		}
		entries = append(entries, Entry{
			Kind: KindSection,
			Name: string(name),
			Pos:  Pos{Addr: sh.Addr},
			New:  size,
		})
	}
	if mem {
		return entries, nil
	}

	// ELF structural overhead: the header itself plus the two header tables.
	overhead := int64(hdr.HeaderSize()) +
		int64(hdr.Phentsize)*int64(hdr.Phnum) +
		int64(hdr.Shentsize)*int64(hdr.Shnum)
	entries = append(entries, Entry{Kind: KindSection, Name: "[elf-headers]", New: overhead})
	covered += overhead

	// Whatever is left is alignment padding between sections, or bytes no
	// section header claims. Reporting it keeps the total honest.
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
