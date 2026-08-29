package xdwarf_test

import (
	"debug/dwarf"
	"debug/elf"
	"os"
	"testing"

	"github.com/soypat/tinyboot/build/xdwarf"
)

// The benchmark fixture is the largest line table in the corpus: 11019 rows
// across 24 compilation units.
const benchFixture = "../../testdata/blink.elf"

// BenchmarkLineRowsXdwarf walks every row of every line unit, resolving each
// row's file name into a reused buffer. This is the shape of work a size
// attribution tool does, and it is the case the package exists to make cheap.
func BenchmarkLineRowsXdwarf(b *testing.B) {
	sec := loadSectionsB(b, benchFixture)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var nameBuf []byte
		var rows int
		for off := 0; off < len(sec.Line); {
			u, next, err := sec.NextLineUnit(off)
			if err != nil {
				b.Fatal(err)
			}
			err = u.VisitRows(func(r xdwarf.Row) error {
				if !r.EndSequence {
					nameBuf, err = u.AppendFileName(nameBuf[:0], r.File)
					if err != nil {
						return err
					}
				}
				rows++
				return nil
			})
			if err != nil {
				b.Fatal(err)
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
	for i := 0; i < b.N; i++ {
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

// loadSectionsB mirrors loadSections for a benchmark's testing.B.
func loadSectionsB(b *testing.B, name string) xdwarf.Sections {
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
	for _, s := range ef.Sections {
		var dst *[]byte
		switch s.Name {
		case ".debug_line":
			dst = &sec.Line
		case ".debug_line_str":
			dst = &sec.LineStr
		case ".debug_str":
			dst = &sec.Str
		default:
			continue
		}
		data, err := s.Data()
		if err != nil {
			b.Fatal(err)
		}
		*dst = data
	}
	return sec
}
