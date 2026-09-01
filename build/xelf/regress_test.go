package xelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

var fixtures = []string{
	"../../testdata/blink.elf",
	"../../testdata/helloc.elf",
	"../../testdata/pca10040-blinky.elf",
}

// TestHeaderAgainstStdlib cross-checks the decoded header against debug/elf.
// It regresses the Class32 Entry field, which was decoded with Uint16 and so
// truncated a 32-bit entry point to its low 16 bits.
func TestHeaderAgainstStdlib(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			fp, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer fp.Close()
			want, err := elf.NewFile(fp)
			if err != nil {
				t.Fatal(err)
			}
			var f File
			if err = f.Read(fp); err != nil {
				t.Fatal(err)
			}
			got := f.Header()
			if got.Entry != want.Entry {
				t.Errorf("Entry=%#x want %#x", got.Entry, want.Entry)
			}
			if int(got.Machine) != int(want.Machine) {
				t.Errorf("Machine=%v want %v", got.Machine, want.Machine)
			}
			if int(got.Shnum) != len(want.Sections) {
				t.Errorf("Shnum=%d want %d", got.Shnum, len(want.Sections))
			}
			if int(got.Phnum) != len(want.Progs) {
				t.Errorf("Phnum=%d want %d", got.Phnum, len(want.Progs))
			}
		})
	}
}

// TestHeaderPutRoundTrip regresses the Class32 Entry encoder alongside its decoder.
func TestHeaderPutRoundTrip(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			fp, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer fp.Close()
			var f File
			if err = f.Read(fp); err != nil {
				t.Fatal(err)
			}
			want := f.Header()
			var buf [headerSize64]byte
			n, err := want.Put(buf[:])
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := DecodeHeader(buf[:n])
			if err != nil {
				t.Fatal(err)
			}
			if got.Entry != want.Entry {
				t.Errorf("round trip Entry=%#x want %#x", got.Entry, want.Entry)
			}
			if got.Shoff != want.Shoff || got.Phoff != want.Phoff {
				t.Errorf("round trip Shoff=%#x/%#x Phoff=%#x/%#x", got.Shoff, want.Shoff, got.Phoff, want.Phoff)
			}
		})
	}
}

// TestProgIndexNoPanic regresses Prog bounds-checking against len(f.sections)
// while indexing f.progs. Every fixture has far more sections than progs, so
// the old bounds check admitted out-of-range indices.
func TestProgIndexNoPanic(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			fp, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer fp.Close()
			var f File
			if err = f.Read(fp); err != nil {
				t.Fatal(err)
			}
			if f.NumSections() <= f.NumProgs() {
				t.Skipf("fixture does not exercise the bug: %d sections, %d progs", f.NumSections(), f.NumProgs())
			}
			for i := 0; i < f.NumProgs(); i++ {
				if _, err := f.Prog(i); err != nil {
					t.Fatalf("Prog(%d): %s", i, err)
				}
			}
			// Indices past the prog count must error, not panic or succeed.
			for _, bad := range []int{f.NumProgs(), f.NumSections() - 1, -1} {
				if _, err := f.Prog(bad); err == nil {
					t.Errorf("Prog(%d) returned nil error, want OOB", bad)
				}
			}
		})
	}
}

// TestDecodeRelFieldOrder regresses the swapped Off/Info fields in DecodeRel.
// ELF declares Elf32_Rel{r_offset, r_info} and Elf64_Rel{r_offset, r_info}; the
// offset comes first. debug/elf's Rel32/Rel64 are the oracle.
func TestDecodeRelFieldOrder(t *testing.T) {
	fp, err := os.Open("../../testdata/pca10040-blinky.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	var f File
	if err = f.Read(fp); err != nil {
		t.Fatal(err)
	}
	sec, err := f.SectionByName(".rel.debug_info")
	if err != nil {
		t.Fatal(err)
	}
	data, err := sec.AppendData(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8*4 {
		t.Fatalf("expected a populated .rel.debug_info, got %d bytes", len(data))
	}
	bo := f.Header().ByteOrder()
	rd := bytes.NewReader(data)
	for i := 0; i < 16; i++ {
		var want elf.Rel32
		if err := binary.Read(rd, bo, &want); err != nil {
			t.Fatal(err)
		}
		got, n, err := DecodeRel(data[i*8:], Class32, bo)
		if err != nil {
			t.Fatal(err)
		}
		if n != 8 {
			t.Fatalf("DecodeRel n=%d want 8", n)
		}
		if got.Off != uint64(want.Off) || got.Info != uint64(want.Info) {
			t.Fatalf("rel[%d]: got Off=%#x Info=%#x, want Off=%#x Info=%#x",
				i, got.Off, got.Info, want.Off, want.Info)
		}
	}
}

// TestApplyRelocationsARM checks that relocating .debug_info actually changes
// bytes. With Off/Info swapped the symbol index read as ~0, every record hit the
// "symNo == 0 { continue }" branch, and the function returned nil having applied
// nothing -- so a nil error alone does not demonstrate the path works.
func TestApplyRelocationsARM(t *testing.T) {
	fp, err := os.Open("../../testdata/pca10040-blinky.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	var f File
	if err = f.Read(fp); err != nil {
		t.Fatal(err)
	}
	syms, err := f.AppendTableSymbols(nil)
	if err != nil {
		t.Fatal(err)
	}
	var infoIdx int
	for i := 0; i < f.NumSections(); i++ {
		s, _ := f.Section(i)
		if name, _ := s.Name(); name == ".debug_info" {
			infoIdx = i
			break
		}
	}
	if infoIdx == 0 {
		t.Fatal("no .debug_info section")
	}
	info, err := f.Section(infoIdx)
	if err != nil {
		t.Fatal(err)
	}
	rels, ok := f.RelocationsFor(infoIdx)
	if !ok {
		t.Fatal("no relocation section targets .debug_info")
	}
	relData, err := rels.AppendData(nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := info.AppendData(nil)
	if err != nil {
		t.Fatal(err)
	}
	after := append([]byte(nil), before...)

	err = ApplyRelocations(after, relData, syms, f.Header())
	// Unhandled relocation types are tolerable; anything else is not.
	if relErr, ok := err.(RelocError); ok {
		if relErr.IsOOB() || relErr.IsBadSymIdx() {
			t.Fatalf("relocation failed: %s", relErr)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("ApplyRelocations changed nothing; the relocation path is not being exercised")
	}
}

func TestFitsAt(t *testing.T) {
	b := make([]byte, 8)
	for _, tc := range []struct {
		off, size uint64
		want      bool
	}{
		{0, 4, true},
		{4, 4, true},  // ends exactly at the buffer end: must be accepted
		{5, 4, false}, // runs one byte past
		{8, 0, true},
		{0, 9, false},
		{^uint64(0), 4, false}, // off+size overflows uint64
		{^uint64(0) - 2, 4, false},
	} {
		if got := fitsAt(b, tc.off, tc.size); got != tc.want {
			t.Errorf("fitsAt(len=%d, off=%d, size=%d)=%v want %v", len(b), tc.off, tc.size, got, tc.want)
		}
	}
}
