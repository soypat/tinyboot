package main

import (
	"debug/elf"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/github.com/soypat/picobin"
	"github.com/github.com/soypat/picobin/elfutil"
)

const (
	_ = 1 << (iota * 10)
	kB
	MB
)

type Flags struct {
	block int
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
		fmt.Fprintf(output, "\tavailable commands: [info, dump]\n")
		fmt.Fprintf(output, "Example:\n\tpicobin info <ELF-filename>\n")
		flag.PrintDefaults()
	}
	flag.IntVar(&flags.block, "block", -1, "Specify a single block to analyze")
	flag.Parse()
	command := flag.Arg(0)
	source := flag.Arg(1)
	// First check command argument.
	if command == "" {
		flag.Usage()
		return errors.New("missing command argument")
	}
	var cmd func(*elf.File, Flags) error
	switch command {
	case "info":
		cmd = info

	case "dump":
		cmd = dump

	default:
		flag.Usage()
		return errors.New("uknown command: " + command)
	}

	// Next check filename.
	if source == "" {
		flag.Usage()
		return errors.New("missing filename argument")
	}
	file, err := elf.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()

	// Finally run command.
	return cmd(file, flags)
}

func info(f *elf.File, flags Flags) error {
	blocks, start, err := getBlocks(f)
	if err != nil {
		return err
	}
	addr := start
	for i, block := range blocks {
		if flags.block >= 0 && i != flags.block {
			addr += int64(block.Link)
			continue
		}

		fmt.Printf("BLOCK%d @ Addr=%#x Size=%d Items=%d\n", i, addr, block.Size(), len(block.Items))
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

func dump(f *elf.File, flags Flags) error {
	blocks, start, err := getBlocks(f)
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
		n, err := elfutil.ReadAtAddr(f, addr+int64(blockSize), data)
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

func getBlocks(f *elf.File) ([]picobin.Block, int64, error) {
	seenAddrs := make(map[int]struct{})
	uromStart, _, err := elfutil.GetROMAddr(f)
	romStart := int64(uromStart)
	if err != nil {
		return nil, 0, err
	}
	ROM := make([]byte, 2*MB)
	flashEnd, err := elfutil.ReadAtAddr(f, romStart, ROM[:])
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
