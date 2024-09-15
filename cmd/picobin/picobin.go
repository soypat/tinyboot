package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/github.com/soypat/picobin"
)

const (
	_ = 1 << (iota * 10)
	kB
	MB
)

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()
	filename := flag.Arg(0)
	if filename == "" {
		return errors.New("missing filename argument")
	}
	file, err := elf.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var flash [2 * MB]byte
	const flashAddr = 0x10000000
	flashEnd, err := readAddr(file, flashAddr, flash[:])
	if err != nil {
		return err
	}
	start0, _, err := picobin.NextBlockIdx(flash[:flashEnd])
	if err != nil {
		return err
	}
	var blocks []picobin.Block
	var blkaddr []int
	start := start0
	for {
		absAddr := start + flashAddr
		block, _, err := picobin.DecodeBlock(flash[start:flashEnd])
		if err != nil {
			return fmt.Errorf("decoding block at Addr=%#x: %w", absAddr, err)
		}
		blocks = append(blocks, block)
		blkaddr = append(blkaddr, absAddr)
		nextStart := start + block.Link
		if nextStart == start0 {
			break // Found last block.
		}
		start = nextStart
	}
	for i, block := range blocks {
		addr := blkaddr[i]
		fmt.Printf("BLOCK%d @ Addr=%#x Size=%d Items=%d\n", i, addr, block.Size(), len(block.Items))
		for _, item := range block.Items {
			fmt.Printf("\t%s\n", item.String())
		}
	}
	return nil
}

func readAddr(f *elf.File, addr int64, b []byte) (int, error) {
	clear(b)
	end := addr + int64(len(b))
	maxReadIdx := 0
	for _, section := range f.Sections {
		saddr := int64(section.Addr)
		if saddr >= addr && saddr < end {
			data, err := section.Data()
			if err != nil {
				return 0, err
			}
			off := int(saddr - addr)
			n := copy(b[off:], data)
			maxReadIdx = max(maxReadIdx, n+off)
		}
	}
	return maxReadIdx, nil
}

func clear[E any](a []E) {
	var z E
	for i := range a {
		a[i] = z
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
