package main

import (
	"bytes"
	"debug/elf"
	"os"
	"testing"
)

func TestDump(t *testing.T) {
	file := "../../testdata/blink.elf"
	flags := Flags{readsize: 2 * MB, argSourcename: file, flashend: defaultFlashEnd}
	fp, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(fp)
	if err != nil {
		t.Fatal(err)
	}
	elfrom, elfStartAddr, err := elfROM(f, flags)
	if err != nil {
		t.Fatal(err)
	}
	// This creates a new uf2 at same location as file with .uf2 extension.
	err = uf2conv(fp, flags)
	if err != nil {
		t.Fatal(err)
	}
	uf2Filename := changeExtension(file, "uf2")
	fpuf2, err := os.Open(uf2Filename)
	if err != nil {
		t.Fatal(err)
	}
	uf2blocks, err := newUF2File(fpuf2, flags)
	if err != nil {
		t.Fatal(err)
	}
	uf2rom, uf2StartAddr, err := uf2ROM(uf2blocks, flags)
	if err != nil {
		t.Fatal(err)
	}
	if elfStartAddr != uf2StartAddr {
		t.Errorf("ELF/UF2 ROM start address mismatch %#x != %#x", elfStartAddr, uf2StartAddr)
	}
	if len(elfrom) != len(uf2rom) {
		t.Error("ELF/UF2 ROM length mismatch", len(elfrom), len(uf2rom))
	}
	if !bytes.Equal(elfrom, uf2rom) {
		t.Error("ELF/UF2 content mismatch")
	}
}
