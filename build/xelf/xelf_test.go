package xelf

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestFile_Read_blink(t *testing.T) {
	fp, err := os.Open("../../testdata/blink.elf")
	if err != nil {
		t.Fatal(err)
	}
	testFile(t, fp, 30)
}

func TestFile_Read_helloc(t *testing.T) {
	fp, err := os.Open("../../testdata/helloc.elf")
	if err != nil {
		t.Fatal(err)
	}
	f := testFile(t, fp, 36)
	nsect := f.NumSections()

	// Generate relocation data.
	var allrel []byte
	for i := 0; i < nsect; i++ {
		s, _ := f.Section(i)
		sh := s.SectionHeader()
		if sh.Type != SecTypeRel && sh.Type != SecTypeRelA {
			continue
		}
		allrel, _ = s.AppendData(allrel)
	}
	if len(allrel) == 0 {
		t.Fatal("no relocation data")
	}
	syms, err := f.AppendTableSymbols(nil)
	if err != nil {
		t.Fatal("getting symbol table", err)
	}
	hdr := f.Header()
	for i := 0; i < nsect; i++ {
		s, _ := f.Section(i)
		sname, _ := s.Name()
		suffix := dwarfSuffix(sname)
		if suffix == "" {
			continue
		}
		data, _ := s.AppendData(nil)
		err = ApplyRelocations(data, allrel, syms, hdr)
		if err != nil {
			t.Fatalf("failure to apply relocation to %q: %s", sname, err)
		}
	}
}

func testFile(t *testing.T, r io.ReaderAt, wantSecs int) *File {
	var f File
	err := f.Read(r)
	if err != nil {
		t.Fatal(err)
	}
	nsect := f.NumSections()
	nprog := f.NumProgs()
	if nsect != wantSecs {
		t.Fatalf("expected %d sections, got %d", wantSecs, nsect)
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
		if hdr.SizeOnFile != sz {
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
		if !sec.IsProgAlloc() {
			continue
		}
		pidx, err := sec.OfProg()
		if err != nil && err != errSectionAliasDup {
			// Sections may alias several progs, ignore those cases.
			t.Errorf("OfProg for %s failed: %s", sec, err)
			continue
		}

		t.Logf("Section%d of Prog%d %q %q...", i, pidx, name, data[:min(len(data), 12)])
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
		if hdr.SizeOnFile != uint64(sz) {
			t.Error("size mismatch for uncompressed file")
		}
	}

	syms, err := f.AppendTableSymbols(nil)
	if err != nil {
		t.Error("querying symbols", err)
	}

	for _, sym := range syms {
		str, err := f.AppendSymStr(nil, sym.Name)
		if err != nil {
			// Go standard library ignores errors in querying invalid strings.
			t.Fatalf("symbol name unable to be queried: %s", err)
		} else if len(str) > 0 {
			t.Logf("symbol %q", str)
		}
	}
	return &f
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func dwarfSuffix(sname string) string {
	switch {
	case strings.HasPrefix(sname, ".debug_"):
		return sname[7:]
	case strings.HasPrefix(sname, ".zdebug_"):
		return sname[8:]
	default:
		return ""
	}
}
