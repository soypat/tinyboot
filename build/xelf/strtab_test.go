package xelf

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestAppendStrLongName covers a string-table entry longer than the fixed read
// buffer. TinyGo writes a reflect type's every method into the symbol naming it,
// which reaches 1.6kB in a program that uses reflection, and a decoder that
// looked for the terminator in one bufferful rejected the whole binary with
// "name too long or bad data".
func TestAppendStrLongName(t *testing.T) {
	// Names either side of the buffer boundary, plus one spanning several fills.
	names := []string{
		"short",
		strings.Repeat("a", fileBufSize-1),
		strings.Repeat("b", fileBufSize),
		strings.Repeat("c", fileBufSize+1),
		patterned(4*fileBufSize + 7),
		"tail",
	}
	var strtab []byte
	offs := make([]int64, len(names))
	for i, n := range names {
		offs[i] = int64(len(strtab))
		strtab = append(strtab, n...)
		strtab = append(strtab, 0)
	}

	var f File
	f.sections = []section{{}}
	fs := FileSection{f: &f, sindex: 0}
	sec := fs.ptr()
	sec.SizeOnFile = uint64(len(strtab))
	sec.sr = *io.NewSectionReader(bytes.NewReader(strtab), 0, int64(len(strtab)))

	for i, want := range names {
		got, err := fs.appendStr(nil, offs[i])
		if err != nil {
			t.Fatalf("name %d (%d bytes): %s", i, len(want), err)
		}
		if string(got) != want {
			t.Fatalf("name %d: got %d bytes, want %d", i, len(got), len(want))
		}
	}

	// Appending must respect a destination that already holds bytes.
	dst, err := fs.appendStr([]byte("PFX:"), offs[4])
	if err != nil {
		t.Fatal(err)
	}
	if string(dst) != "PFX:"+names[4] {
		t.Error("appendStr did not preserve the existing destination bytes")
	}

	// A table whose last entry has no terminator must error, not run off the end
	// or hand back a name the file never contained.
	unterm := []byte(patterned(3 * fileBufSize))
	var f2 File
	f2.sections = []section{{}}
	fs2 := FileSection{f: &f2, sindex: 0}
	fs2.ptr().SizeOnFile = uint64(len(unterm))
	fs2.ptr().sr = *io.NewSectionReader(bytes.NewReader(unterm), 0, int64(len(unterm)))
	got, err := fs2.appendStr([]byte("PFX:"), 0)
	if err == nil {
		t.Error("unterminated final string accepted")
	}
	if string(got) != "PFX:" {
		t.Errorf("failed appendStr left %d bytes on the destination", len(got)-4)
	}
}

// TestSectionNameBufferAliasing guards the destination SectionByName passes:
// f.buf itself. A name needing more than one fill must not be corrupted by the
// buffer its own reads go through.
func TestSectionNameBufferAliasing(t *testing.T) {
	// Every byte differs by position: a name of one repeated character would
	// survive the buffer being refilled under it, since each chunk would look
	// like the one it replaced.
	long := patterned(2*fileBufSize + 3)
	strtab := append([]byte{0}, append([]byte(long), 0)...)

	var f File
	f.sections = []section{{}}
	fs := FileSection{f: &f, sindex: 0}
	sec := fs.ptr()
	sec.SizeOnFile = uint64(len(strtab))
	sec.sr = *io.NewSectionReader(bytes.NewReader(strtab), 0, int64(len(strtab)))

	got, err := fs.appendStr(f.buf[:0], 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != long {
		at := -1
		for i := 0; i < len(got) && i < len(long); i++ {
			if got[i] != long[i] {
				at = i
				break
			}
		}
		t.Fatalf("name read into f.buf came back corrupted: %d bytes (want %d), first differing byte at %d",
			len(got), len(long), at)
	}
}

// patterned returns an n-byte printable string whose content depends on
// position, so a chunk overwritten by a later read cannot pass for the one it
// replaced.
func patterned(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + (i*7+i/26)%26)
	}
	return string(b)
}
