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

// ROMAddr returns the read-only memory start and end address of the ELF file.
func ROMAddr(f *elf.File) (startAddr, endAddr uint64, err error) {
	if len(f.Sections) == 0 || len(f.Progs) == 0 {
		return 0, 0, errors.New("no sections and/or progs in ELF")
	}

	sectionStartAddr := ^uint64(0)
	for _, section := range f.Sections {
		if !SectionIsROM(section) {
			continue
		}
		if section.Addr < sectionStartAddr {
			sectionStartAddr = section.Addr // Sections define our lowest address. Progs may have bootloader memory.
		}
	}
	progStartAddr := ^uint64(0)
	for _, prog := range f.Progs {
		if !ProgIsROM(prog) {
			continue
		}
		endProg := prog.Paddr + prog.Memsz
		if progStartAddr < prog.Paddr {
			progStartAddr = prog.Paddr
		}
		if endProg > endAddr {
			endAddr = endProg
		}
	}
	// Find the lowest section address.
	// The lowest program memory address is before the first section. This means
	// that there is some extra data loaded at the start of the image that
	// should be discarded.
	// Example: ELF files where .text doesn't start at address 0 because
	// there is a bootloader at the start.
	startAddr = sectionStartAddr

	if startAddr == 0 && endAddr == 0 {
		return 0, 0, errors.New("no ELF ROM memory found")
	} else if startAddr == 0 {
		return 0, 0, errors.New("no ELF ROM sections found")
	} else if endAddr == 0 {
		return 0, 0, errors.New("no ELF ROM prog memory found")
	} else if startAddr >= endAddr {
		return 0, 0, errors.New("inconsistent ELF ROM labelling between sections and prog")
	} else if endAddr-startAddr > math.MaxInt {
		return startAddr, endAddr, fmt.Errorf("ELF ROM size overflows int %#x..%#x (%d)", startAddr, endAddr, endAddr-startAddr)
	}
	return startAddr, endAddr, nil
}

// EnsureROMContiguous checks ROM program memory is contiguously represented between startAddr and endAddr addresses and returns error if not contiguous
// to within maxContiguousDiff bytes.
func EnsureROMContiguous(f *elf.File, startAddr, endAddr, maxContiguousDiff uint64) error {
	if maxContiguousDiff > math.MaxInt {
		return errors.New("contiguous diff overflows int, possible signed integer conversion bug")
	}
	// TODO(soypat): maybe use a more elegant, non-brute approach... but really this is more than good enough for non-adversarial input. O(n) time for sorted inputs. O(n^2) for adversarial input. ELF is typically more or less sorted...
	contiguousUpTo := startAddr
	for c := 0; c < len(f.Progs); c++ {
		for _, prog := range f.Progs {
			pstart := prog.Paddr
			pend := pstart + prog.Memsz
			maxContiguousAddr := contiguousUpTo + maxContiguousDiff
			if !ProgIsROM(prog) || pstart > maxContiguousAddr || !aliases(contiguousUpTo, maxContiguousAddr+1, pstart, pend) {
				continue
			}
			if maxContiguousDiff == 0 && pstart < contiguousUpTo {
				return fmt.Errorf("ROM memory not contiguous between %#x..%#x, found data overlap at %#x", startAddr, endAddr, contiguousUpTo)
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
	return fmt.Errorf("ROM memory not contiguous between %#x..%#x, missing data after %#x", startAddr, endAddr, contiguousUpTo)
}

// ReadROMAt reads from the binary sections representing read-only-memory (ROM) starting at address addr.
func ReadROMAt(f *elf.File, b []byte, addr uint64) (int, error) {
	romStart, romEnd, err := ROMAddr(f)
	if err != nil {
		return 0, err
	}
	end := addr + uint64(len(b))
	if !aliases(addr, end, romStart, romEnd) {
		return 0, errors.New("attempted to read completely out of ELF ROM bounds")
	}

	clear(b)
	maxReadIdx := 0
	for _, prog := range f.Progs {
		paddr := prog.Paddr
		pend := paddr + prog.Memsz
		if !ProgIsROM(prog) || !aliases(addr, end, paddr, pend) {
			continue
		}

		progOff := dim(addr, paddr)
		bOff := dim(paddr, addr)
		if progOff > math.MaxInt64 {
			return maxReadIdx, errors.New("ELF prog size overflows int64")
		}
		n, err := prog.ReadAt(b[bOff:], int64(progOff))
		if err != nil && err != io.EOF {
			return maxReadIdx, err
		}
		maxReadIdx = max(maxReadIdx, n+int(bOff))
	}
	return maxReadIdx, nil
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

func dim[T integer](a, b T) T {
	if a < b {
		return 0
	}
	return a - b
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
