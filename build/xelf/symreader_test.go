package xelf

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestSymReader_matchesTable checks the streaming walk against the materialized
// table, entry for entry and name for name, through a window too small to hold
// the table so refills are exercised. Names are read into buffers sized
// exactly by NameLen.
func TestSymReader_matchesTable(t *testing.T) {
	for _, name := range append(fixtures, "../../testdata/gz-reloc.o") {
		var f File
		fp, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		defer fp.Close()
		if err := f.Read(fp); err != nil {
			t.Fatal(name, err)
		}
		want, err := f.AppendTableSymbols(nil)
		if err != nil {
			t.Fatal(name, err)
		}
		var sr SymReader
		if err := sr.Reset(&f, make([]byte, 100)); err != nil {
			t.Fatal(name, err)
		}
		if sr.NumSymbols() != len(want)+1 {
			t.Errorf("%s: NumSymbols=%d, table holds %d after the null entry", name, sr.NumSymbols(), len(want))
		}
		var i int
		for sym, ok := sr.Next(); ok; sym, ok = sr.Next() {
			if i >= len(want) {
				t.Fatalf("%s: walk yields more than the table's %d symbols", name, len(want))
			}
			if sym != want[i] {
				t.Errorf("%s: symbol %d is %+v, table has %+v", name, i+1, sym, want[i])
			}
			if sr.Index() != i+1 {
				t.Errorf("%s: Index=%d want %d", name, sr.Index(), i+1)
			}
			wantName, err := f.AppendSymStr(nil, want[i].Name)
			if err != nil {
				t.Fatal(err)
			}
			n, err := sr.NameLen(sym)
			if err != nil {
				t.Fatal(err)
			}
			dst := make([]byte, n)
			if n, err = sr.ReadName(dst, sym); err != nil {
				t.Fatal(name, err)
			}
			if !bytes.Equal(dst[:n], wantName) {
				t.Errorf("%s: symbol %d named %q, table says %q", name, i+1, dst[:n], wantName)
			}
			i++
		}
		if err := sr.Err(); err != nil {
			t.Fatal(name, err)
		}
		if i != len(want) {
			t.Errorf("%s: walk yields %d symbols, table holds %d", name, i, len(want))
		}
	}
}

// TestReadName_shortBuffer checks a buffer one byte short of a name is refused
// rather than filled with a truncated name, for symbols and sections alike.
func TestReadName_shortBuffer(t *testing.T) {
	fp, err := os.Open(fixtures[0])
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	var f File
	if err := f.Read(fp); err != nil {
		t.Fatal(err)
	}
	var sr SymReader
	sr.Reset(&f, make([]byte, 512))
	var checked bool
	for sym, ok := sr.Next(); ok && !checked; sym, ok = sr.Next() {
		n, _ := sr.NameLen(sym)
		if n < 2 {
			continue
		}
		if _, err := sr.ReadName(make([]byte, n-1), sym); err != io.ErrShortBuffer {
			t.Errorf("symbol name of %d bytes into %d: got %v, want io.ErrShortBuffer", n, n-1, err)
		}
		checked = true
	}
	s, err := f.SectionByName(".text")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadName(make([]byte, len(".text")-1)); err != io.ErrShortBuffer {
		t.Errorf(".text into %d bytes: got %v, want io.ErrShortBuffer", len(".text")-1, err)
	}
	if n, err := s.NameLen(); err != nil || n != len(".text") {
		t.Errorf(".text NameLen=%d, %v", n, err)
	}
}

// TestRead_reuseAllocs holds Read and the symbol walk to their promise: once a
// File's tables have held a binary, reading it again and walking its symbols
// allocates nothing.
func TestRead_reuseAllocs(t *testing.T) {
	data, err := os.ReadFile(fixtures[0])
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(data)
	var f File
	if err := f.Read(r); err != nil {
		t.Fatal(err)
	}
	var sr SymReader
	win, name := make([]byte, 512), make([]byte, 512)
	allocs := testing.AllocsPerRun(10, func() {
		if err := f.Read(r); err != nil {
			t.Fatal(err)
		}
		if err := sr.Reset(&f, win); err != nil {
			t.Fatal(err)
		}
		for sym, ok := sr.Next(); ok; sym, ok = sr.Next() {
			if _, err := sr.ReadName(name, sym); err != nil {
				t.Fatal(err)
			}
		}
		if sr.Err() != nil {
			t.Fatal(sr.Err())
		}
	})
	if allocs != 0 {
		t.Errorf("Read and symbol walk allocate %v times", allocs)
	}

	hdr, err := f.ReadHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	if int(hdr.Shnum) != f.NumSections() || int(hdr.Phnum) != f.NumProgs() {
		t.Errorf("ReadHeader counts %d sections, %d progs; Read %d, %d", hdr.Shnum, hdr.Phnum, f.NumSections(), f.NumProgs())
	}
}
