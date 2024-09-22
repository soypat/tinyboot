package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/soypat/picobin/uf2"
)

func uf2info(r io.ReaderAt, flags Flags) error {
	uf2blocks, err := newUF2File(r, flags)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "UF2 %d blocks:\n", len(uf2blocks))
	h := sha256.New()

	for i := range uf2blocks {
		block := uf2blocks[i]

		data, err := block.Data()
		var sum []byte
		if err != nil {
			fmt.Fprintf(os.Stdout, "\tblock%d: %s\n", block.BlockNum, err.Error())
		} else {
			h.Reset()
			h.Write(data)
			sum = h.Sum(sum[:0])
		}
		fmt.Fprintf(os.Stdout, "\t%s sha256=%x\n", block.String(), sum)
	}
	ROM, romstart, err := uf2ROM(uf2blocks, flags)
	if err != nil {
		return err
	}
	blocks, block0start, err := romBlocks(ROM, romstart)
	if err != nil {
		return err
	}
	return blockInfo(blocks, romstart+uint64(block0start), flags)
}

func uf2conv(r io.ReaderAt, flags Flags) error {
	f, err := newElfFile(r, flags)
	if err != nil {
		return err
	}
	ROM, romStartAddr, err := elfROM(f, flags)
	if err != nil {
		return err
	}
	if romStartAddr+uint64(len(ROM)) > math.MaxUint32 {
		return fmt.Errorf("address %#x overflows uint32 (max for UF2)", romStartAddr+uint64(len(ROM)))
	}
	formatter := uf2.Formatter{ChunkSize: 256, FamilyID: uint32(flags.familyID), Flags: uf2.FlagFamilyIDPresent}
	uf2prog := make([]byte, 0, len(ROM)+len(ROM)/uf2.BlockSize*(32+4))
	uf2prog, _, err = formatter.AppendTo(uf2prog, ROM, uint32(romStartAddr))
	if err != nil {
		return err
	}
	filename := changeExtension(flags.argSourcename, "uf2")
	fmt.Println("writing file", filename)
	return os.WriteFile(filename, uf2prog, 0777)
}

func uf2ROM(uf2blocks []uf2.Block, flags Flags) (ROM []byte, romAddr uint64, err error) {
	rd, err := uf2.NewBlocksReaderAt(uf2blocks)
	if err != nil {
		return nil, 0, err
	}
	start, end := rd.Addrs()
	if end > uint32(flags.flashend) {
		end = uint32(flags.flashend)
	}
	romsize := int(end) - int(start)
	if romsize < 0 {
		return nil, 0, fmt.Errorf("invalid addresses or bad flash address flag start=%#x, flashlim=%#x", start, flags.flashend)
	} else if romsize > int(flags.readsize) {
		fmt.Println("limiting ROM read")
		romsize = int(flags.readsize)
	}
	ROM = make([]byte, romsize)
	n, err := rd.ReadAt(ROM, int64(start))
	if err != nil {
		return nil, 0, err
	} else if n != len(ROM) {
		fmt.Println("unexpected short read:", n, "of", len(ROM))
	}
	return ROM, uint64(start), nil
}

func newUF2File(r io.ReaderAt, _ Flags) ([]uf2.Block, error) {
	wrapper := &readeratReader{ReaderAt: r}
	var blocks []uf2.Block = make([]uf2.Block, 0, 256)
	scratch := make([]byte, 1024*uf2.BlockSize)
	blocks, _, err := uf2.DecodeAppendBlocks(blocks, wrapper, scratch)
	return blocks, err
}

type readeratReader struct {
	io.ReaderAt
	counter int
}

func (rar *readeratReader) Read(b []byte) (int, error) {
	n, err := rar.ReaderAt.ReadAt(b, int64(rar.counter))
	rar.counter += n
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return n, err
}

func changeExtension(filename, newextension string) string {
	dotIdx := strings.IndexByte(filename, '.')
	if dotIdx < 0 {
		dotIdx = len(filename)
	}
	return filename[:dotIdx] + "." + newextension
}
