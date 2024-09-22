package elfutil

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
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
	if startAddr >= endAddr {
		return 0, 0, errors.New("no ROM sections found")
	} else if endAddr-startAddr > math.MaxInt {
		return startAddr, endAddr, fmt.Errorf("ROM size overflows int %#x..%#x (%d)", startAddr, endAddr, endAddr-startAddr)
	}
	return startAddr, endAddr, nil
}

// EnsureROMContiguous checks ROM program memory is contiguously represented between startAddr and endAddr addresses and returns error if not contiguous.
func EnsureROMContiguous(f *elf.File, startAddr, endAddr uint64) error {
	// TODO(soypat): maybe use a more elegant, non-brute approach... but really this is more than good enough for non-adversarial input. O(n) time for sorted inputs. O(n^2) for adversarial input. ELF is typically more or less sorted...
	contiguousUpTo := startAddr
	for c := 0; c < len(f.Progs); c++ {
		for _, prog := range f.Progs {
			pstart := prog.Paddr
			pend := pstart + prog.Memsz
			if !ProgIsROM(prog) || !aliases(contiguousUpTo, contiguousUpTo+1, pstart, pend) {
				continue
			}
			contiguousUpTo = pend
			if contiguousUpTo >= endAddr {
				return nil
			}
		}
	}
	if contiguousUpTo == startAddr {
		return errors.New("start address lower than ROM")
	}
	return fmt.Errorf("ROM memory not contiguous between %#x..%#x, only up to %#x", startAddr, endAddr, contiguousUpTo)
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

type integer interface {
	~int | ~int64 | ~uint64
}

func aliases[T integer](start0, end0, start1, end1 T) bool {
	return start0 < end1 && end0 > start1
}

func clear[E any](a []E) {
	var z E
	for i := range a {
		a[i] = z
	}
}

func max[T integer](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T integer](a, b T) T {
	if a < b {
		return a
	}
	return b
}
