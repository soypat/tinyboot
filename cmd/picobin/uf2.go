package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

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
