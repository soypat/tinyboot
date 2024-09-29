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
	nsect := f.NumSections()
	nprog := f.NumProgs()
	if nsect != 30 {
		t.Fatal("expected 30 sections", nsect)
	}
	for i := 0; i < nsect; i++ {
		sec, err := f.Section(i)
		if err != nil {
			t.Error(err)
		}
		name, err := sec.Name()
		if err != nil {
			t.Error(err)
		}
		secgot, err := f.SectionByName(name)
		if err != nil {
			t.Errorf("failed to acquire section %q by name", name)
		}
		if err == nil && secgot.sindex != sec.sindex {
			t.Fatalf("oh god, wtf happened %d != %d", secgot.sindex, sec.sindex)
		}
		hdr := sec.SectionHeader()
		sz := uint64(sec.Size())
		if hdr.FileSize != sz {
			t.Error("size mismatch for uncompressed data")
		}
		data, err := sec.AppendData(nil)
		if err != nil && hdr.Type != SecTypeNobits {
			t.Error("section data", err)
		} else if err == nil && hdr.Type == SecTypeNobits {
			t.Error("section data success on no bits read", err)
		} else if hdr.Type == SecTypeNobits {
			continue
		}
		if len(data) != int(sz) {
			t.Error("length of data no match size")
		}
		t.Logf("Section%d %q %q...", i, name, data[:min(len(data), 12)])
	}
	for i := 0; i < nprog; i++ {
		prog, err := f.Prog(i)
		if err != nil {
			t.Error(err)
		}
		sz := prog.Size()
		if sz < 0 {
			t.Error("negative size")
		}
		hdr := prog.ProgHeader()
		if hdr.Filesz != uint64(sz) {
			t.Error("size mismatch for uncompressed file")
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
