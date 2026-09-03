package xdwarf_test

import (
	"debug/dwarf"
	"debug/elf"
	"io"
	"os"
	"testing"

	"github.com/soypat/tinyboot/build/xdwarf"
)

// The benchmark fixture is the largest line table in the corpus: 11019 rows
// across 24 compilation units.
const benchFixture = "../../testdata/blink.elf"

// benchAux clears the largest unit header in the fixture with room to spare, so
// the walk never has to grow and retry.
const benchAux = 4096

// BenchmarkLineRowsXdwarf walks every row of every line unit, resolving each
// row's file name into a reused buffer. This is the shape of work a size
// attribution tool does, and it is the case the package exists to make cheap.
func BenchmarkLineRowsXdwarf(b *testing.B) {
	sec, size := loadSectionsB(b, benchFixture)
	// One unit and one scratch buffer for every walk: reusing them is the
	// documented way to drive this API, and what makes decoding allocation-free
	// once the tables have grown to their high-water mark.
	var u xdwarf.LineUnit
	aux := make([]byte, benchAux)
	nameBuf := make([]byte, 0, benchAux)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var rows int
		for off := int64(0); off < size; {
			next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
			if err != nil {
				b.Fatal(err)
			}
			for r := range u.Rows {
				if !r.EndSequence {
					nameBuf, err = u.AppendFileName(nameBuf[:0], r.File)
					if err != nil {
						b.Fatal(err)
					}
				}
				rows++
			}
			off = next
		}
		if rows == 0 {
			b.Fatal("no rows")
		}
	}
}

// BenchmarkLineRowsStdlib is the same walk through debug/dwarf, for comparison.
func BenchmarkLineRowsStdlib(b *testing.B) {
	fp, err := os.Open(benchFixture)
	if err != nil {
		b.Fatal(err)
	}
	defer fp.Close()
	ef, err := elf.NewFile(fp)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		d, err := ef.DWARF()
		if err != nil {
			b.Fatal(err)
		}
		var rows int
		r := d.Reader()
		for {
			cu, err := r.Next()
			if err != nil {
				b.Fatal(err)
			}
			if cu == nil {
				break
			}
			if cu.Tag != dwarf.TagCompileUnit {
				r.SkipChildren()
				continue
			}
			lr, err := d.LineReader(cu)
			if err != nil || lr == nil {
				r.SkipChildren()
				continue
			}
			var le dwarf.LineEntry
			for lr.Next(&le) == nil {
				if !le.EndSequence && le.File != nil {
					_ = le.File.Name
				}
				rows++
			}
			r.SkipChildren()
		}
		if rows == 0 {
			b.Fatal("no rows")
		}
	}
}

// loadSectionsB mirrors loadSections for a benchmark's testing.B. It reads
// through debug/elf rather than xelf so the benchmark measures xdwarf, not the
// container parser, and the fixture needs no relocation.
func loadSectionsB(b *testing.B, name string) (xdwarf.Sections, int64) {
	b.Helper()
	fp, err := os.Open(name)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { fp.Close() })
	ef, err := elf.NewFile(fp)
	if err != nil {
		b.Fatal(err)
	}
	sec := xdwarf.Sections{ByteOrder: ef.ByteOrder}
	var lineSize int64
	for _, s := range ef.Sections {
		var dst *io.ReaderAt
		switch s.Name {
		case ".debug_line":
			dst, lineSize = &sec.Line, int64(s.Size)
		case ".debug_line_str":
			dst = &sec.LineStr
		case ".debug_str":
			dst = &sec.Str
		default:
			continue
		}
		if s.ReaderAt == nil {
			b.Fatalf("%s is not backed by a ReaderAt", s.Name)
		}
		*dst = s.ReaderAt
	}
	if sec.Line == nil {
		b.Fatalf("%s has no .debug_line", name)
	}
	return sec, lineSize
}
