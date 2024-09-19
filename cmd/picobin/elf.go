package main

import (
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/github.com/soypat/picobin"
	"github.com/github.com/soypat/picobin/elfutil"
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

	blocks, start, err := getBlocks(f, flags)
	if err != nil {
		return err
	}
	addr := start
	for i, block := range blocks {
		if flags.block >= 0 && i != flags.block {
			addr += int64(block.Link)
			continue
		}

		fmt.Printf("\nBLOCK%d @ Addr=%#x Size=%d Items=%d\n", i, addr, block.Size(), len(block.Items))
		for _, item := range block.Items {
			fmt.Printf("\t%s\n", item.String())
		}
		addr += int64(block.Link)
	}
	for i, block := range blocks {
		err = block.Validate()
		if err != nil {
			fmt.Printf("BLOCK%d failed to validate: %s\n", i, err.Error())
		}
	}
	return nil
}

func elfdump(r io.ReaderAt, flags Flags) error {
	f, err := newElfFile(r, flags)
	if err != nil {
		return err
	}
	blocks, start, err := getBlocks(f, flags)
	if err != nil {
		return err
	}
	addr := start
	for i, block := range blocks {
		if flags.block >= 0 && i != flags.block || len(block.Items) >= 1 && block.Items[0].ItemType() == picobin.ItemTypeIgnored {
			addr += int64(block.Link)
			continue
		}
		blockSize := block.Size()
		dataSize := block.Link - blockSize
		if dataSize < 0 {
			break // Last block.
		}
		data := make([]byte, dataSize)
		n, err := elfutil.ReadAt(f, data, addr+int64(blockSize))
		if err != nil {
			return err
		} else if n == 0 {
			return errors.New("unable to extract data after block")
		}
		fmt.Printf("BLOCK%d @ Addr=%#x dump:\n%s", i, addr, hex.Dump(data))
		addr += int64(block.Link)
	}
	return nil
}

func getBlocks(f *elf.File, flags Flags) ([]picobin.Block, int64, error) {
	seenAddrs := make(map[int]struct{})
	uromStart, uromEnd, err := elfutil.GetROMAddr(f)
	if err != nil {
		return nil, 0, err
	}
	romStart := int64(uromStart)
	romSize := uromEnd - uromStart
	if romSize > uint64(flags.readsize) {
		fmt.Printf("ROM %d too large, limiting to %d\n", romSize, flags.readsize)
		romSize = uint64(flags.readsize)
	}
	ROM := make([]byte, romSize)
	flashEnd, err := elfutil.ReadAt(f, ROM[:], romStart)
	if err != nil {
		return nil, 0, err
	}
	start0, _, err := picobin.NextBlockIdx(ROM[:flashEnd])
	if err != nil {
		return nil, 0, err
	}
	seenAddrs[start0] = struct{}{}
	var blocks []picobin.Block
	start := start0
	startAbs := int64(start) + romStart
	for {
		absAddr := int64(start) + romStart
		block, _, err := picobin.DecodeBlock(ROM[start:flashEnd])
		if err != nil {
			return blocks, startAbs, fmt.Errorf("decoding block at Addr=%#x: %w", absAddr, err)
		}
		blocks = append(blocks, block)
		nextStart := start + block.Link
		_, alreadySeen := seenAddrs[nextStart]
		if alreadySeen {
			if nextStart == start0 {
				break // Found last block.
			}
			return blocks, startAbs, fmt.Errorf("odd cyclic block at Addr=%#x", absAddr)
		}
		seenAddrs[nextStart] = struct{}{}
		start = nextStart
	}
	return blocks, startAbs, nil
}

// helper function that discards sections and program memory of no interest to us.
func newElfFile(r io.ReaderAt, flags Flags) (*elf.File, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
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
