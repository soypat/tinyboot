package main

import (
	"debug/elf"
	"testing"
)

func TestDump(t *testing.T) {
	fp, err := elf.Open("../../blink.elf")
	if err != nil {
		t.Fatal(err)
	}
	dump(fp, Flags{block: 0})
}
