package elfutil

import (
	"debug/elf"
	"errors"
	"io"
)

func GetROMAddr(f *elf.File) (start, end uint64, err error) {
	// Find the lowest section address.
	startAddr := ^uint64(0)
	endAddr := uint64(0)
	for _, section := range f.Sections {
		if section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if section.Addr < startAddr {
			startAddr = section.Addr
		}
		if section.Addr+section.Size > endAddr {
			endAddr = section.Addr + section.Size
		}
	}
	if startAddr > endAddr {
		return 0, 0, errors.New("no ROM sections found")
	}
	return startAddr, end, nil
}

// ReadAtAddr reads from the binary sections representing read-only-memory (ROM) starting at address addr.
func ReadAtAddr(f *elf.File, addr int64, b []byte) (int, error) {
	clear(b)
	end := addr + int64(len(b))
	maxReadIdx := 0
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Filesz == 0 || prog.Off == 0 {
			continue
		}
		paddr := int64(prog.Paddr)
		pend := paddr + int64(prog.Memsz)
		if aliases(addr, end, paddr, pend) {
			progOff := max(0, int(addr-paddr))
			bOff := max(0, int(paddr-addr))
			n, err := prog.ReadAt(b[bOff:], int64(progOff))
			if err != nil && err != io.EOF {
				return maxReadIdx, err
			}
			maxReadIdx = max(maxReadIdx, n+bOff)
		}
	}
	return maxReadIdx, nil
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
