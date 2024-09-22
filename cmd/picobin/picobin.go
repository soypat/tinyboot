package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/soypat/picobin"
)

const (
	_ = 1 << (iota * 10)
	kB
	MB
)

const (
	defaultFlashEnd = 0x20000000
	rp2350FamilyID  = 0xe48bff59
)

type Flags struct {
	argSourcename string
	block         int
	readsize      uint
	flashend      uint64
	familyID      uint
}

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var flags Flags
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(output, "\tavailable commands: [elfinfo, elfdump, uf2info]\n")
		fmt.Fprintf(output, "Example:\n\tpicobin info <ELF-filename>\n")
		flag.PrintDefaults()
	}
	flag.IntVar(&flags.block, "block", -1, "Specify a single block to analyze")
	flag.UintVar(&flags.readsize, "readlim", 2*MB, "Size of haystack to look for blocks in, starting at ROM start address")
	flag.Uint64Var(&flags.flashend, "flashend", defaultFlashEnd, "End limit of flash memory. All memory past this limit is ignored.")
	flag.UintVar(&flags.familyID, "familyid", rp2350FamilyID, "Family ID for UF2 generation.")
	flag.Parse()
	command := flag.Arg(0)
	source := flag.Arg(1)
	flags.argSourcename = source
	// First check command argument.
	if command == "" {
		flag.Usage()
		return errors.New("missing command argument")
	}
	var cmd func(io.ReaderAt, Flags) error
	switch command {
	case "elfinfo":
		cmd = elfinfo

	case "elfdump":
		cmd = elfdump

	case "uf2info":
		cmd = uf2info

	case "uf2conv":
		cmd = uf2conv

	default:
		flag.Usage()
		return errors.New("uknown command: " + command)
	}

	// Next check filename.
	if source == "" {
		flag.Usage()
		return errors.New("missing filename argument")
	}
	file, err := os.Open(source)
	// file, err := elf.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()

	// Finally run command.
	return cmd(file, flags)
}

func romBlocks(ROM []byte, romStartAddr uint64) (blocks []picobin.Block, block0Off int, err error) {
	block0Off, _, err = picobin.NextBlockIdx(ROM)
	if err != nil {
		return nil, 0, err
	}
	seenAddrs := make(map[int]struct{})
	seenAddrs[block0Off] = struct{}{}
	start := block0Off
	for {
		absAddr := uint64(start) + romStartAddr
		block, _, err := picobin.DecodeBlock(ROM[start:])
		if err != nil {
			return blocks, block0Off, fmt.Errorf("decoding block at Addr=%#x: %w", absAddr, err)
		}
		blocks = append(blocks, block)
		nextStart := start + block.Link
		_, alreadySeen := seenAddrs[nextStart]
		if alreadySeen {
			if nextStart == block0Off {
				break // Found last block.
			}
			return blocks, block0Off, fmt.Errorf("odd cyclic block at Addr=%#x", absAddr)
		}
		seenAddrs[nextStart] = struct{}{}
		start = nextStart
	}
	return blocks, block0Off, nil
}

func blockInfo(blocks []picobin.Block, block0StartAddr uint64, flags Flags) (err error) {
	if len(blocks) == 0 {
		return errors.New("no blocks found")
	}
	fmt.Println("ROM Block info:")
	addr := block0StartAddr
	for i, block := range blocks {
		if flags.block >= 0 && i != flags.block {
			addr += uint64(block.Link)
			continue
		}

		fmt.Printf("BLOCK%d @ Addr=%#x Size=%d Items=%d\n", i, addr, block.Size(), len(block.Items))
		for _, item := range block.Items {
			fmt.Printf("\t%s\n", item.String())
		}
		addr += uint64(block.Link)
	}
	for i, block := range blocks {
		err = block.Validate()
		if err != nil {
			fmt.Printf("BLOCK%d failed to validate:\n\t%s\n", i, err.Error())
		}
	}
	return nil
}

func romDump(ROM []byte, startAddr uint64, flags Flags) (err error) {
	blocks, block0Start, err := romBlocks(ROM, startAddr)
	if err != nil {
		return err
	}
	off := block0Start
	for i, block := range blocks {
		if flags.block >= 0 && i != flags.block || len(block.Items) >= 1 && block.Items[0].ItemType() == picobin.ItemTypeIgnored {
			off += int(block.Link)
			continue
		}
		nextOff := off + block.Link
		if nextOff == block0Start {
			break // Last block.
		}
		addr := startAddr + uint64(off)
		fmt.Printf("BLOCK%d @ Addr=%#x dump:\n%s", i, addr, hex.Dump(ROM[off:nextOff]))
		off += int(block.Link)
	}
	return nil
}
