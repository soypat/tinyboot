package main

import (
	"os"
	"testing"
)

func TestDump(t *testing.T) {
	fp, err := os.Open("../../blink.elf")
	if err != nil {
		t.Fatal(err)
	}
	err = uf2conv(fp, Flags{readsize: 2 * MB, argSourcename: "blink.uf2", flashend: defaultFlashEnd})
	if err != nil {
		t.Fatal(err)
	}
}
