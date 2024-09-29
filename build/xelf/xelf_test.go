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
	for i := 0; i < f.NumSections(); i++ {
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
		t.Logf("Section%d %q", i, name)
	}
}
