package xdwarf_test

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"io"
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

// loadSections addresses the DWARF payloads in an ELF with xelf, wrapping each
// in a relocating reader. Relocatable objects (TinyGo emits .rel.debug_*) carry
// unresolved addresses until those fixups are applied as the bytes are read.
func loadSections(t *testing.T, name string) (xdwarf.Sections, int64) {
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
	sec := xdwarf.Sections{ByteOrder: f.Header().ByteOrder()}
	var lineSize int64
	for i := 0; i < f.NumSections(); i++ {
		s, err := f.Section(i)
		if err != nil {
			t.Fatal(err)
		}
		secName, err := s.Name()
		if err != nil {
			t.Fatal(err)
		}
		var dst *io.ReaderAt
		switch secName {
		case ".debug_line":
			dst, lineSize = &sec.Line, s.Size()
		case ".debug_line_str":
			dst = &sec.LineStr
		case ".debug_str":
			dst = &sec.Str
		default:
			continue
		}
		rr := new(xelf.RelocReaderAt)
		// Unhandled relocation types are expected on these targets and do not
		// invalidate the rest of the section, so rr.Err is not fatal here.
		if _, err := rr.Reset(&f, s); err != nil {
			t.Fatal(err)
		}
		*dst = rr
	}
	if sec.Line == nil || lineSize == 0 {
		t.Fatalf("%s has no .debug_line", name)
	}
	return sec, lineSize
}

// defaultAux is comfortably past the largest unit header in the corpus, so the
// common path is exercised without the grow-and-retry loop kicking in.
const defaultAux = 4096

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
//
// auxSize seeds the scratch buffer. A size too small for some unit's header is
// not an error the caller has to predict: DecodeLineUnit reports how much it
// needs and the same offset is retried, which is what lets the tests run this
// walk with a deliberately tiny buffer.
func collect(t *testing.T, sec xdwarf.Sections, size int64, compDirs map[uint64]string, auxSize int) []row {
	t.Helper()
	var rows []row
	var nameBuf []byte
	var u xdwarf.LineUnit
	aux := make([]byte, auxSize)
	for off := int64(0); off < size; {
		next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
		var small xdwarf.AuxTooSmallError
		if errors.As(err, &small) {
			aux = make([]byte, small.Need)
			continue
		}
		if err != nil {
			t.Fatalf("unit at %d: %s", off, err)
		}
		if next <= off {
			t.Fatalf("unit at %d did not advance", off)
		}
		if dir, ok := compDirs[uint64(u.Offset)]; ok && u.Version < 5 {
			u.CompDir = dir
		}
		for r := range u.Rows {
			out := row{addr: r.Address, line: r.Line, end: r.EndSequence}
			if !r.EndSequence {
				nameBuf, err = u.AppendFileName(nameBuf[:0], r.File)
				if err != nil {
					t.Fatalf("unit at %d: naming row file: %s", off, err)
				}
				out.file = xdwarf.CleanPath(string(nameBuf))
			}
			rows = append(rows, out)
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
			sec, size := loadSections(t, name)
			got := collect(t, sec, size, compDirs, defaultAux)

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
		sec, size := loadSections(t, name)
		var u xdwarf.LineUnit
		aux := make([]byte, defaultAux)
		for off := int64(0); off < size; {
			next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
			if err != nil {
				t.Fatalf("%s unit at %d: %s", name, off, err)
			}
			seen[u.Version]++
			if u.Offset != off {
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

// TestRowsStop pins the iterator's half of the range-over-func contract: once
// yield returns false the walk must return without calling it again. Calling it
// again is a runtime panic, not a quiet bug.
func TestRowsStop(t *testing.T) {
	sec, size := loadSections(t, "../../testdata/helloc.elf")
	var u xdwarf.LineUnit
	if _, err := xdwarf.DecodeLineUnit(&u, sec, 0, size, make([]byte, defaultAux)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for range u.Rows {
		n++
		if n == 3 {
			break
		}
	}
	if n != 3 {
		t.Errorf("visited %d rows after stopping at 3", n)
	}
}

func TestDecodeLineUnitRejectsBadInput(t *testing.T) {
	sec, size := loadSections(t, "../../testdata/helloc.elf")
	var u xdwarf.LineUnit
	aux := make([]byte, defaultAux)
	if _, err := xdwarf.DecodeLineUnit(&u, sec, -1, size, aux); err == nil {
		t.Error("negative offset accepted")
	}
	if _, err := xdwarf.DecodeLineUnit(&u, sec, size+1, size, aux); err == nil {
		t.Error("offset past the section accepted")
	}
	// A section cut short must error rather than panic. The reader still serves
	// the whole file; it is the declared size that lies.
	if _, err := xdwarf.DecodeLineUnit(&u, sec, 0, 12, aux); err == nil {
		t.Error("truncated unit accepted")
	}
	// Every unit's header is larger than this, so every unit must say so rather
	// than decode something wrong.
	var small xdwarf.AuxTooSmallError
	_, err := xdwarf.DecodeLineUnit(&u, sec, 0, size, make([]byte, 16))
	if !errors.As(err, &small) {
		t.Fatalf("aux of 16 bytes accepted, got %v", err)
	}
	// The size it names must actually be enough.
	if _, err := xdwarf.DecodeLineUnit(&u, sec, 0, size, make([]byte, small.Need)); err != nil {
		t.Errorf("aux of the %d bytes reported as needed still failed: %s", small.Need, err)
	}
}

// TestAuxSizeIndependence is the boundary check: the rows a walk produces must
// not depend on how much of the section happens to be resident. A tiny aux puts
// a refill in the middle of nearly every read -- of the opcode stream, of a
// string's scan for its terminator, and of a relocated field -- while an aux
// larger than the section puts one nowhere.
func TestAuxSizeIndependence(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			sec, size := loadSections(t, name)
			want := collect(t, sec, size, nil, int(size)+4096)
			if len(want) == 0 {
				t.Fatal("no rows")
			}
			// collect grows aux to whatever a header needs, so this ends up at
			// the smallest buffer the fixture admits: one header plus the
			// minimum window.
			got := collect(t, sec, size, nil, 1)
			if len(got) != len(want) {
				t.Fatalf("tiny aux produced %d rows, large aux produced %d", len(got), len(want))
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("row %d differs by aux size:\n tiny %+v\nlarge %+v", i, got[i], want[i])
				}
			}
			t.Logf("%d rows identical across aux sizes", len(got))
		})
	}
}

// TestDecodeAllocationsSteadyState pins the claim the API is shaped around: a
// caller that reuses one LineUnit and one aux buffer stops allocating once the
// directory and file tables have grown to their high-water mark. The row
// callback is hoisted because a fresh closure per unit would allocate on its
// own account and mask what the decoder does.
func TestDecodeAllocationsSteadyState(t *testing.T) {
	sec, size := loadSections(t, "../../testdata/blink.elf")
	var u xdwarf.LineUnit
	var nameBuf []byte
	var rows int
	var visitErr error
	visit := func(r xdwarf.Row) bool {
		if !r.EndSequence {
			nameBuf, visitErr = u.AppendFileName(nameBuf[:0], r.File)
			if visitErr != nil {
				return false
			}
		}
		rows++
		return true
	}
	aux := make([]byte, defaultAux)
	walk := func() {
		for off := int64(0); off < size; {
			next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
			if err != nil {
				t.Fatalf("unit at %d: %s", off, err)
			}
			// Rows is called directly rather than ranged over so the hoisted
			// visit function stays the one the walk uses.
			u.Rows(visit)
			if visitErr != nil {
				t.Fatalf("unit at %d: %s", off, visitErr)
			}
			off = next
		}
	}
	walk() // Grow the tables and the name buffer before measuring.
	before := rows
	if n := testing.AllocsPerRun(4, walk); n != 0 {
		t.Errorf("steady-state walk allocates %v times per run", n)
	}
	if rows <= before {
		t.Fatal("the measured walk visited no rows")
	}
}
