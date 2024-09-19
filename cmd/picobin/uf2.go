package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/github.com/soypat/picobin/elfutil"
	"github.com/github.com/soypat/picobin/uf2"
)

func uf2info(r io.ReaderAt, flags Flags) error {
	blocks, err := uf2file(r, flags)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "UF2 %d blocks:\n", len(blocks))
	h := sha256.New()

	for i := range blocks {
		block := blocks[i]

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
	return nil
}

func uf2conv(r io.ReaderAt, flags Flags) error {
	f, err := newElfFile(r, flags)
	if err != nil {
		return err
	}
	start, end, err := elfutil.GetROMAddr(f)
	if err != nil {
		return err
	}
	size := end - start
	if size > uint64(flags.readsize) {
		return fmt.Errorf("flash size too large %d", size)
	} else if start > math.MaxUint32 {
		return fmt.Errorf("address %d overflows uint32 (max for UF2)", start)
	}
	ROM := make([]byte, size)
	n, err := elfutil.ReadAt(f, ROM, int64(start))
	if err != nil {
		return err
	} else if n != len(ROM) {
		return fmt.Errorf("failed to read ELF ROM completely (%d/%d)", n, len(ROM))
	}
	fmt := uf2.Formatter{ChunkSize: 256, FamilyID: uint32(flags.familyID), Flags: uf2.FlagFamilyIDPresent}
	uf2prog := make([]byte, 0, size)
	uf2prog, _, err = fmt.AppendTo(uf2prog, ROM, uint32(start))
	if err != nil {
		return err
	}
	dotIdx := strings.IndexByte(flags.argSourcename, '.')
	if dotIdx < 0 {
		dotIdx = len(flags.argSourcename)
	}
	return os.WriteFile(flags.argSourcename[:dotIdx]+".uf2", uf2prog, 0777)
}

func uf2file(r io.ReaderAt, _ Flags) ([]uf2.Block, error) {
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
