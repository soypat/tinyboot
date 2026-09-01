package elfutil

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"os"
	"testing"

	azlib "github.com/soypat/archive/zlib"
	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xelf"
)

// lineFixture is an uncompressed .debug_line to compress and read back. Its 24
// units and 68KB comfortably outrun any single fill, so a walk over it crosses
// span boundaries many times.
const lineFixture = "../../testdata/blink.elf"

// debugSections returns a fixture's raw .debug_line, .debug_str and
// .debug_line_str. The fixture carries a DWARF 5 unit whose file names are
// offsets into the string sections, so a walk needs all three.
func debugSections(t *testing.T) (line, str, lineStr []byte) {
	t.Helper()
	fp, err := os.Open(lineFixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fp.Close() })
	var f xelf.File
	if err := f.Read(fp); err != nil {
		t.Fatal(err)
	}
	get := func(name string) []byte {
		fsec, err := f.SectionByName(name)
		if err != nil {
			return nil
		}
		data, err := fsec.AppendData(nil)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	line = get(".debug_line")
	if len(line) == 0 {
		t.Fatalf("%s has no .debug_line", lineFixture)
	}
	return line, get(".debug_str"), get(".debug_line_str")
}

// deflate wraps b in a zlib stream, standing in for the SHF_COMPRESSED payload
// a toolchain would have written.
func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type lineRow struct {
	addr uint64
	file string
	line uint32
	end  bool
}

// walk decodes every unit reachable through sec.Line and returns the whole line
// matrix.
func walk(t *testing.T, sec xdwarf.Sections, size int64, aux []byte) []lineRow {
	t.Helper()
	var rows []lineRow
	var u xdwarf.LineUnit
	var nameBuf []byte
	for off := int64(0); off < size; {
		next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
		if err != nil {
			t.Fatalf("unit at %d: %s", off, err)
		}
		for row := range u.Rows {
			out := lineRow{addr: row.Address, line: row.Line, end: row.EndSequence}
			if !row.EndSequence {
				var err error
				nameBuf, err = u.AppendFileName(nameBuf[:0], row.File)
				if err != nil {
					t.Fatalf("unit at %d: naming row file: %s", off, err)
				}
				out.file = string(nameBuf)
			}
			rows = append(rows, out)
		}
		off = next
	}
	return rows
}

// newStream returns a reader inflating compressed through buf bytes of lookback.
func newStream(t *testing.T, compressed, buf []byte) *rewindReader {
	t.Helper()
	var zr azlib.Reader
	if err := zr.Configure(azlib.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := zr.Reset(bytes.NewReader(compressed)); err != nil {
		t.Fatal(err)
	}
	var rr rewindReader
	rr.Reset(&zr, buf)
	return &rr
}

// TestStreamedLineTableMatchesResident is the correctness anchor for reading a
// compressed line table without materializing it. Inflating as the decoder walks
// only works because the decoder steps backwards by a bounded amount -- at most
// one aux, when it starts an opcode program inside the header read that
// overshot it -- so the same bytes must yield the same matrix whether they are
// resident or streamed.
func TestStreamedLineTableMatchesResident(t *testing.T) {
	raw, str, lineStr := debugSections(t)
	size := int64(len(raw))
	compressed := deflate(t, raw)
	t.Logf(".debug_line %d bytes, %d compressed", size, len(compressed))
	sec := xdwarf.Sections{Str: bytes.NewReader(str), LineStr: bytes.NewReader(lineStr)}

	// The fixture's largest unit header wants 1867 bytes of aux, so 2048 is
	// about as tight as this walk goes -- and tight is the point, since a small
	// aux means a refill across nearly every read.
	for _, aux := range []int{2048, 4096, 16384} {
		t.Run("aux="+itoa(aux), func(t *testing.T) {
			sec.Line = bytes.NewReader(raw)
			want := walk(t, sec, size, make([]byte, aux))
			if len(want) == 0 {
				t.Fatal("no rows")
			}
			sec.Line = newStream(t, compressed, make([]byte, StreamBufferFor(aux)))
			got := walk(t, sec, size, make([]byte, aux))
			if len(got) != len(want) {
				t.Fatalf("streamed produced %d rows, resident %d", len(got), len(want))
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("row %d differs:\n streamed %+v\n resident %+v", i, got[i], want[i])
				}
			}
			t.Logf("%d rows identical", len(got))
		})
	}
}

// TestStreamBufferTooSmall checks that a lookback buffer below what StreamBufferFor
// asks for fails loudly and says what would have worked, rather than returning
// wrong rows or a bare ErrRewound from the middle of a walk.
func TestStreamBufferTooSmall(t *testing.T) {
	raw, str, lineStr := debugSections(t)
	size := int64(len(raw))
	compressed := deflate(t, raw)

	const aux = 4096
	// Half of what the bound calls for, so the decoder's step back past the
	// header read lands behind the retained bytes.
	small := StreamBufferFor(aux) / 2
	sec := xdwarf.Sections{
		Line:    newStream(t, compressed, make([]byte, small)),
		Str:     bytes.NewReader(str),
		LineStr: bytes.NewReader(lineStr),
	}
	var u xdwarf.LineUnit
	auxBuf := make([]byte, aux)

	var rewound RewoundError
	var err error
	for off := int64(0); off < size; {
		var next int64
		next, err = xdwarf.DecodeLineUnit(&u, sec, off, size, auxBuf)
		if err == nil {
			// LineUnit.Rows reports no error of its own, so a rewind that
			// happens mid-program is only visible on the next unit's decode.
			for range u.Rows {
			}
		}
		if err != nil {
			break
		}
		off = next
	}
	if !errors.As(err, &rewound) {
		t.Fatalf("undersized lookback did not report RewoundError, got %v", err)
	}
	if rewound.Short <= 0 {
		t.Errorf("RewoundError reports a shortfall of %d", rewound.Short)
	}
	t.Logf("reported: %s", rewound)

	// The documented size must actually serve where half of it did not.
	sec.Line = newStream(t, compressed, make([]byte, StreamBufferFor(aux)))
	if rows := walk(t, sec, size, auxBuf); len(rows) == 0 {
		t.Fatal("no rows at StreamBufferFor(aux)")
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// gzFixture is a relocatable object built with compressed debug sections:
//
//	gcc -c -g -gz=zlib -o gz-reloc.o gz-reloc.c
//
// It is the shape this package got wrong once. .debug_line is SHF_COMPRESSED
// and carries .rela.debug_line at the same time, which is ordinary output for
// an object built with -gz -- the gABI's only exclusivity rule for
// SHF_COMPRESSED is against SHF_ALLOC, not against relocations. Its .debug_str
// and .debug_line_str are compressed too, so one file covers both compressed
// paths: the one read at arbitrary offsets and the one carrying relocations.
const gzFixture = "../../testdata/gz-reloc.o"

// TestCompressedRelocatable reads a -gz object through LoadDWARF and checks the
// line matrix against debug/dwarf. Addresses are the point: a relocation left
// unapplied leaves them zero, which no row count or file name would catch.
func TestCompressedRelocatable(t *testing.T) {
	want := stdlibLineRows(t, gzFixture)
	if len(want) == 0 {
		t.Fatal("oracle produced no rows")
	}

	fp, err := os.Open(gzFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	var f xelf.File
	if err := f.Read(fp); err != nil {
		t.Fatal(err)
	}
	var zr azlib.Reader
	if err := zr.Configure(azlib.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	const aux = 4096
	rr := DWARFReaders{Zlib: &zr, Stream: make([]byte, StreamBufferFor(aux))}
	var sec xdwarf.Sections
	size, err := LoadDWARF(&sec, &rr, &f)
	if err != nil {
		t.Fatalf("LoadDWARF: %s", err)
	}

	got := walk(t, sec, size, make([]byte, aux))
	if len(got) != len(want) {
		t.Fatalf("got %d rows, debug/dwarf produced %d", len(got), len(want))
	}
	var nonzero int
	for i := range got {
		// The oracle resolves names against its own tables; addresses and lines
		// are what the relocation and decompression paths decide.
		if got[i].addr != want[i].addr || got[i].line != want[i].line || got[i].end != want[i].end {
			t.Fatalf("row %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
		if got[i].addr != 0 {
			nonzero++
		}
	}
	if nonzero == 0 {
		t.Fatal("every address is zero, so the relocations were never applied")
	}
	t.Logf("%d rows match debug/dwarf, %d with relocated addresses", len(got), nonzero)
}

// stdlibLineRows is the debug/dwarf oracle, which does its own decompression
// and relocation.
func stdlibLineRows(t *testing.T, name string) []lineRow {
	t.Helper()
	ef, err := elf.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ef.Close() })
	d, err := ef.DWARF()
	if err != nil {
		t.Skipf("stdlib could not read DWARF from %s: %s", name, err)
	}
	var rows []lineRow
	r := d.Reader()
	for {
		cu, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if cu == nil {
			break
		}
		if cu.Tag != dwarf.TagCompileUnit {
			r.SkipChildren()
			continue
		}
		lr, err := d.LineReader(cu)
		if err != nil {
			t.Fatal(err)
		}
		if lr == nil {
			r.SkipChildren()
			continue
		}
		var le dwarf.LineEntry
		for lr.Next(&le) == nil {
			rows = append(rows, lineRow{addr: le.Address, line: uint32(le.Line), end: le.EndSequence})
		}
		r.SkipChildren()
	}
	return rows
}
