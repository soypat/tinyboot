package xdwarf_test

import (
	"debug/dwarf"
	"debug/elf"
	"os"
	"path"
	"testing"

	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xelf"
)

// The three fixtures between them cover .debug_line versions 3, 4 and 5, ELF32
// ARM and ELF64 x86-64, and both linked and relocatable debug sections.
var fixtures = []string{
	"../../testdata/blink.elf",           // DWARF 5 info, line v3.
	"../../testdata/helloc.elf",          // line v5, with .debug_line_str.
	"../../testdata/pca10040-blinky.elf", // line v4, needs relocation.
}

// loadSections pulls the DWARF payloads out of an ELF with xelf, applying any
// relocations that target them. Relocatable objects (TinyGo emits .rel.debug_*)
// carry unresolved addresses until this runs.
func loadSections(t *testing.T, name string) xdwarf.Sections {
	t.Helper()
	fp, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fp.Close() })

	var f xelf.File
	if err := f.Read(fp); err != nil {
		t.Fatal(err)
	}
	syms, symErr := f.AppendTableSymbols(nil)
	hdr := f.Header()

	sec := xdwarf.Sections{ByteOrder: hdr.ByteOrder()}
	for i := 0; i < f.NumSections(); i++ {
		s, err := f.Section(i)
		if err != nil {
			t.Fatal(err)
		}
		secName, err := s.Name()
		if err != nil {
			t.Fatal(err)
		}
		var dst *[]byte
		switch secName {
		case ".debug_line":
			dst = &sec.Line
		case ".debug_line_str":
			dst = &sec.LineStr
		case ".debug_str":
			dst = &sec.Str
		default:
			continue
		}
		data, err := s.AppendData(nil)
		if err != nil {
			t.Fatal(err)
		}
		if rels, ok := f.RelocationsFor(i); ok && symErr == nil {
			relData, err := rels.AppendData(nil)
			if err != nil {
				t.Fatal(err)
			}
			// Unhandled relocation types are expected on these targets and do
			// not invalidate the rest of the section.
			_ = xelf.ApplyRelocations(data, relData, syms, hdr)
		}
		*dst = data
	}
	if len(sec.Line) == 0 {
		t.Fatalf("%s has no .debug_line", name)
	}
	return sec
}

type row struct {
	addr uint64
	file string
	line uint32
	end  bool
}

// collect walks every line unit in the section and returns the full matrix.
//
// compDirs maps a unit's offset in .debug_line to the compilation directory
// that unit's relative paths resolve against. Before DWARF 5 that value lives
// in .debug_info, which xdwarf does not parse, so it is supplied here as an
// input the way a real caller would supply it.
func collect(t *testing.T, sec xdwarf.Sections, compDirs map[uint64]string) []row {
	t.Helper()
	var rows []row
	var nameBuf []byte
	for off := 0; off < len(sec.Line); {
		u, next, err := sec.NextLineUnit(off)
		if err != nil {
			t.Fatalf("unit at %d: %s", off, err)
		}
		if next <= off {
			t.Fatalf("unit at %d did not advance", off)
		}
		if dir, ok := compDirs[u.Offset]; ok && u.Version < 5 {
			u.CompDir = dir
		}
		err = u.VisitRows(func(r xdwarf.Row) error {
			out := row{addr: r.Address, line: r.Line, end: r.EndSequence}
			if !r.EndSequence {
				nameBuf, err = u.AppendFileName(nameBuf[:0], r.File)
				if err != nil {
					return err
				}
				out.file = xdwarf.CleanPath(string(nameBuf))
			}
			rows = append(rows, out)
			return nil
		})
		if err != nil {
			t.Fatalf("unit at %d: visiting rows: %s", off, err)
		}
		off = next
	}
	return rows
}

// stdlibRows produces the same matrix using debug/dwarf, as the oracle. It also
// returns each line unit's compilation directory, keyed by the unit's offset in
// .debug_line (a compile unit's DW_AT_stmt_list).
func stdlibRows(t *testing.T, name string) ([]row, map[uint64]string) {
	t.Helper()
	fp, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	ef, err := elf.NewFile(fp)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ef.DWARF()
	if err != nil {
		t.Skipf("stdlib could not read DWARF from %s: %s", name, err)
		return nil, nil
	}
	var rows []row
	compDirs := make(map[uint64]string)
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
		if off, ok := cu.Val(dwarf.AttrStmtList).(int64); ok {
			dir, _ := cu.Val(dwarf.AttrCompDir).(string)
			compDirs[uint64(off)] = dir
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
		for {
			err := lr.Next(&le)
			if err != nil {
				break
			}
			out := row{addr: le.Address, line: uint32(le.Line), end: le.EndSequence}
			if !le.EndSequence && le.File != nil {
				out.file = path.Clean(le.File.Name)
			}
			rows = append(rows, out)
		}
		r.SkipChildren()
	}
	return rows, compDirs
}

// TestLineTableAgainstStdlib is the correctness anchor for this package: the
// line matrix xdwarf produces must match the one debug/dwarf produces, row for
// row, across all three DWARF line versions in the corpus.
func TestLineTableAgainstStdlib(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			want, compDirs := stdlibRows(t, name)
			if len(want) == 0 {
				t.Skip("stdlib produced no line rows")
			}
			got := collect(t, loadSections(t, name), compDirs)

			if len(got) != len(want) {
				t.Fatalf("got %d rows, stdlib produced %d", len(got), len(want))
			}
			mismatches := 0
			for i := range got {
				if got[i] != want[i] {
					mismatches++
					if mismatches <= 10 {
						t.Errorf("row %d:\n got %+v\nwant %+v", i, got[i], want[i])
					}
				}
			}
			if mismatches > 10 {
				t.Errorf("... and %d more mismatched rows", mismatches-10)
			}
			t.Logf("%d line rows matched", len(got))
		})
	}
}

// TestLineUnitVersions documents which line table versions the corpus actually
// exercises, so a regression that silently stops covering one is visible.
func TestLineUnitVersions(t *testing.T) {
	seen := make(map[uint16]int)
	for _, name := range fixtures {
		sec := loadSections(t, name)
		for off := 0; off < len(sec.Line); {
			u, next, err := sec.NextLineUnit(off)
			if err != nil {
				t.Fatalf("%s unit at %d: %s", name, off, err)
			}
			seen[u.Version]++
			if u.Offset != uint64(off) {
				t.Errorf("%s: unit at %d reports Offset=%d", name, off, u.Offset)
			}
			off = next
		}
	}
	for _, want := range []uint16{3, 4, 5} {
		if seen[want] == 0 {
			t.Errorf("no line table of version %d in the corpus", want)
		}
	}
	t.Logf("line unit versions: %v", seen)
}

func TestVisitRowsStop(t *testing.T) {
	sec := loadSections(t, "../../testdata/helloc.elf")
	u, _, err := sec.NextLineUnit(0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = u.VisitRows(func(r xdwarf.Row) error {
		n++
		if n == 3 {
			return xdwarf.ErrStopVisit
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ErrStopVisit surfaced as an error: %s", err)
	}
	if n != 3 {
		t.Errorf("visited %d rows after stopping at 3", n)
	}
}

func TestNextLineUnitRejectsBadOffset(t *testing.T) {
	sec := loadSections(t, "../../testdata/helloc.elf")
	if _, _, err := sec.NextLineUnit(-1); err == nil {
		t.Error("negative offset accepted")
	}
	if _, _, err := sec.NextLineUnit(len(sec.Line) + 1); err == nil {
		t.Error("offset past the section accepted")
	}
	// A truncated section must error rather than panic.
	short := xdwarf.Sections{Line: sec.Line[:12], ByteOrder: sec.ByteOrder}
	if _, _, err := short.NextLineUnit(0); err == nil {
		t.Error("truncated unit accepted")
	}
}
