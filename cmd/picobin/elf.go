package main

import (
	"debug/elf"
	"fmt"
	"io"

	"github.com/soypat/picobin/build/elfutil"
)

func elfinfo(r io.ReaderAt, flags Flags) error {
	f, err := newElfFile(r, flags)
	if err != nil {
		return err
	}
	fmt.Println("ELF info:")
	totalSize := 0

	for _, sect := range f.Sections {
		fmt.Printf("\t%s Addr=%#x Size=%d\n", sect.Name, sect.Addr, sect.Size)
		totalSize += int(sect.Size)
	}
	fmt.Printf("total program memory=%d\n", totalSize)
	ROM, romstart, err := elfROM(f, flags)
	if err != nil {
		return err
	}
	blocks, block0off, err := romBlocks(ROM, romstart)
	if err != nil {
		return err
	}
	block0Addr := romstart + uint64(block0off)
	return blockInfo(blocks, block0Addr, flags)
}

func elfdump(r io.ReaderAt, flags Flags) error {
	f, err := newElfFile(r, flags)
	if err != nil {
		return err
	}
	ROM, romstart, err := elfROM(f, flags)
	if err != nil {
		return err
	}
	return romDump(ROM, romstart, flags)
}

func elfROM(f *elf.File, flags Flags) (ROM []byte, romAddr uint64, err error) {
	uromStart, uromEnd, err := elfutil.ROMAddr(f)
	if err != nil {
		return nil, 0, err
	}
	err = elfutil.EnsureROMContiguous(f, uromStart, uromEnd)
	if err != nil {
		return nil, uromStart, err
	}
	romSize := uromEnd - uromStart
	if romSize > uint64(flags.readsize) {
		fmt.Printf("ROM %d too large, limiting to %d\n", romSize, flags.readsize)
		romSize = uint64(flags.readsize)
	}
	ROM = make([]byte, romSize)
	flashEnd, err := elfutil.ReadAt(f, ROM[:], uromStart)
	if err != nil {
		return nil, 0, err
	} else if flashEnd > int(flags.readsize) {
		return nil, 0, fmt.Errorf("flash size too large %d", flashEnd) // Should never happen...
	}
	return ROM[:flashEnd], uromStart, nil
}

// helper function that discards sections and program memory of no interest to us.
func newElfFile(r io.ReaderAt, flags Flags) (*elf.File, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("attempt to read ELF format: %w", err)
	}

	var sections []*elf.Section
	var progs []*elf.Prog
	for _, sect := range f.Sections {
		if elfutil.SectionIsROM(sect) && sect.Addr < uint64(flags.flashend) {
			sections = append(sections, sect)
		}
	}
	for _, prog := range f.Progs {
		if elfutil.ProgIsROM(prog) && prog.Paddr < uint64(flags.flashend) {
			progs = append(progs, prog)
		}
	}
	f.Sections = sections
	f.Progs = progs
	return f, nil
}
