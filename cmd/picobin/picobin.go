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
	"golang.org/x/exp/constraints"
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
		n, err := readAddr(f, addr+int64(blockSize), data)
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
	var flash [2 * MB]byte
	const flashAddr = 0x10000000
	flashEnd, err := readAddr(f, flashAddr, flash[:])
	if err != nil {
		return nil, 0, err
	}
	start0, _, err := picobin.NextBlockIdx(flash[:flashEnd])
	if err != nil {
		return nil, 0, err
	}
	var blocks []picobin.Block
	start := start0
	startAbs := int64(start) + flashAddr
	for {
		absAddr := start + flashAddr
		block, _, err := picobin.DecodeBlock(flash[start:flashEnd])
		if err != nil {
			return blocks, startAbs, fmt.Errorf("decoding block at Addr=%#x: %w", absAddr, err)
		}
		blocks = append(blocks, block)
		nextStart := start + block.Link
		if nextStart == start0 {
			break // Found last block.
		}
		start = nextStart
	}
	return blocks, startAbs, nil
}

func readAddr(f *elf.File, addr int64, b []byte) (int, error) {
	clear(b)
	end := addr + int64(len(b))
	maxReadIdx := 0
	for _, section := range f.Sections {
		saddr := int64(section.Addr)
		send := saddr + int64(section.Size)
		if aliases(addr, end, saddr, send) {
			data, err := section.Data()
			if err != nil {
				return 0, err
			}
			sectOff := max(0, int(addr-saddr))
			bOff := max(0, int(saddr-addr))
			n := copy(b[bOff:], data[sectOff:])
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

func max[T constraints.Integer](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T constraints.Integer](a, b T) T {
	if a < b {
		return a
	}
	return b
}
