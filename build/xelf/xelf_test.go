package xelf

import (
	"os"
	"testing"
)

func TestFile_Read(t *testing.T) {
	fp, err := os.Open("../../testdata/blink.elf")
	if err != nil {
		t.Fatal(err)
	}
	var f File
	err = f.Read(fp)
	if err != nil {
		t.Fatal(err)
	}
}
