package elfutil

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

// SectionIsROM checks if the section is meant to exist on firmware.
func SectionIsROM(section *elf.Section) bool {
	return section.Type == elf.SHT_PROGBITS && section.Flags&elf.SHF_ALLOC != 0
}

// ProgIsROM checks if the program header memory lives on the read only memory (flash).
func ProgIsROM(prog *elf.Prog) bool {
	return prog.Type == elf.PT_LOAD && prog.Filesz > 0 && prog.Off > 0

}

func GetROMAddr(f *elf.File) (startAddr, endAddr uint64, err error) {
	// Find the lowest section address.
	startAddr = ^uint64(0)
	for _, prog := range f.Progs {
		if !ProgIsROM(prog) {
			continue
		}
		if prog.Paddr < startAddr {
			startAddr = prog.Paddr
		}
		endProg := prog.Paddr + prog.Memsz
		if endProg > endAddr {
			endAddr = endProg
		}
	}
	if startAddr > endAddr {
		return 0, 0, errors.New("no ROM sections found")
	}
	return startAddr, endAddr, nil
}

// ReadAt reads from the binary sections representing read-only-memory (ROM) starting at address addr.
func ReadAt(f *elf.File, b []byte, addr int64) (int, error) {
	if addr < 0 {
		return 0, errors.New("negative address")
	}
	clear(b)
	end := addr + int64(len(b))
	maxReadIdx := 0
	for _, prog := range f.Progs {
		paddr := int64(prog.Paddr)
		pend := paddr + int64(prog.Memsz)
		if !ProgIsROM(prog) || !aliases(addr, end, paddr, pend) {
			continue
		}

		progOff := max(0, addr-paddr)
		bOff := max(0, paddr-addr)
		n, err := prog.ReadAt(b[bOff:], progOff)
		if err != nil && err != io.EOF {
			return maxReadIdx, err
		}
		maxReadIdx = max(maxReadIdx, n+int(bOff))
	}
	return maxReadIdx, nil
}

func ReplaceSection(f *elf.File, sectionName string, newData []byte) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("ELF section %q not found", sectionName)
	} else if section.Size != section.FileSize {
		return errors.New("cannot replace compressed section")
	}

	return nil
}

func aliases(start0, end0, start1, end1 int64) bool {
	return start0 < end1 && end0 > start1
}

func clear[E any](a []E) {
	var z E
	for i := range a {
		a[i] = z
	}
}

func max[T ~int | ~int64](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T ~int | ~int64](a, b T) T {
	if a < b {
		return a
	}
	return b
}
