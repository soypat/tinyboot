package xobj

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/soypat/tinyboot/build"
	"github.com/soypat/tinyboot/build/xelf"
	"github.com/soypat/tinyboot/build/xwasm"
)

var fixtures = []string{
	"../../testdata/blink.elf",
	"../../testdata/helloc.elf",
	"../../testdata/pca10040-blinky.elf",
	"../../testdata/gz-reloc.o",
	"../../testdata/tiny.wasm",
}

func readFixture(t testing.TB, name string, f *File) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Read(bytes.NewReader(data)); err != nil {
		t.Fatal(name, err)
	}
	return data
}

// sectionName reads a section's name into a buffer sized by its length.
func sectionName(t testing.TB, f *File, i int) string {
	t.Helper()
	n, err := f.SectionNameLen(i)
	if err != nil {
		t.Fatal(err)
	}
	name := make([]byte, n)
	if _, err := f.ReadSectionName(name, i); err != nil {
		t.Fatal(err)
	}
	return string(name)
}

// symbolName reads a symbol's name into a buffer sized by its length.
func symbolName(t testing.TB, f *File, sym Symbol) string {
	t.Helper()
	n, err := f.SymbolNameLen(sym)
	if err != nil {
		t.Fatal(err)
	}
	name := make([]byte, n)
	if _, err := f.ReadSymbolName(name, sym); err != nil {
		t.Fatal(err)
	}
	return string(name)
}

// TestSections checks the section model accounts for the file: contents and
// headers never claim more than the file holds, and in a WebAssembly module,
// which has no padding, exactly what it holds.
func TestSections(t *testing.T) {
	for _, name := range fixtures {
		var f File
		data := readFixture(t, name, &f)
		total := f.HeaderBytes()
		var code, debug bool
		for s := range f.Sections {
			total += int64(s.Size)
			secName := sectionName(t, &f, s.Index)
			if s.Off+s.Size > uint64(len(data)) {
				t.Errorf("%s: section %q runs past the file", name, secName)
			}
			code = code || s.Class == ClassCode
			if s.Class == ClassCode && !s.InLines {
				t.Errorf("%s: code section %q outside the line address space", name, secName)
			}
			if isDWARF := strings.HasPrefix(secName, ".debug_"); isDWARF != (s.Class == ClassDebug) {
				t.Errorf("%s: section %q classed %v", name, secName, s.Class)
			}
			debug = debug || s.Class == ClassDebug
		}
		if err := f.Err(); err != nil {
			t.Fatal(name, err)
		}
		if !code || !debug {
			t.Errorf("%s: code section found %v, debug section found %v", name, code, debug)
		}
		switch {
		case total > int64(len(data)):
			t.Errorf("%s: sections and headers claim %d bytes of a %d byte file", name, total, len(data))
		case f.Format() == FormatWasm && total != int64(len(data)):
			t.Errorf("%s: sections and headers claim %d bytes of a %d byte module", name, total, len(data))
		}
		sections, _, err := f.HeaderCounts(bytes.NewReader(data))
		if err != nil || sections != f.NumSections() {
			t.Errorf("%s: HeaderCounts says %d sections (%v), Read found %d", name, sections, err, f.NumSections())
		}
	}
}

// TestSymbols_ELF checks the walk yields exactly the table's sized symbols, and
// that an offset plus its section's address gives back the symbol's value.
func TestSymbols_ELF(t *testing.T) {
	for _, name := range fixtures {
		var f File
		readFixture(t, name, &f)
		ef, ok := f.ELF()
		if !ok {
			continue
		}
		table, err := ef.AppendTableSymbols(nil)
		if err != nil {
			t.Fatal(err)
		}
		var want int
		for _, sym := range table {
			typ := xelf.SymType(sym.Info & 0xf)
			if (typ == xelf.SymTypeFunc || typ == xelf.SymTypeObject) && sym.Shndx > 0 && xelf.SectionIndex(sym.Shndx) < xelf.SecIdxReserveLo {
				want++
			}
		}
		var got int
		for sym := range f.Symbols {
			got++
			s, _ := ef.Section(sym.Section)
			value := table[sym.Index-1].Value
			if sym.Func && ef.Header().Machine == xelf.MachineARM {
				value &^= 1 // Thumb bit.
			}
			symName := symbolName(t, &f, sym)
			if s.SectionHeader().Addr+sym.Off != value {
				t.Errorf("%s: %s at section offset %#x, value %#x", name, symName, sym.Off, value)
			}
			wantName, _ := ef.AppendSymStr(nil, table[sym.Index-1].Name)
			if symName != string(wantName) {
				t.Errorf("%s: symbol %d named %q, want %q", name, sym.Index, symName, wantName)
			}
		}
		if err := f.Err(); err != nil {
			t.Fatal(name, err)
		}
		if got != want {
			t.Errorf("%s: walk yields %d symbols, table holds %d", name, got, want)
		}
	}
}

// TestSymbols_matchesLLVM checks every ELF symbol the walk yields against
// llvm-nm: same name, address and size. llvm-nm lists more -- untyped and
// absolute symbols -- so only the walk's side is checked for membership.
func TestSymbols_matchesLLVM(t *testing.T) {
	nm := llvmTool(t, "llvm-nm")
	for _, name := range fixtures {
		var f File
		readFixture(t, name, &f)
		ef, ok := f.ELF()
		if !ok {
			continue
		}
		out, err := exec.Command(nm, "-S", "--defined-only", name).Output()
		if err != nil {
			t.Fatal(name, err)
		}
		type key struct {
			name       string
			addr, size uint64
		}
		listed := make(map[key]int)
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 4 {
				continue
			}
			addr, err1 := strconv.ParseUint(fields[0], 16, 64)
			size, err2 := strconv.ParseUint(fields[1], 16, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			listed[key{fields[3], addr, size}]++
		}
		var n int
		for sym := range f.Symbols {
			s, _ := ef.Section(sym.Section)
			k := key{symbolName(t, &f, sym), s.SectionHeader().Addr + sym.Off, sym.Size}
			if listed[k] == 0 {
				t.Errorf("%s: %s at %#x size %d not listed by llvm-nm", name, k.name, k.addr, k.size)
			}
			listed[k]--
			n++
		}
		if n == 0 {
			t.Errorf("%s: no symbols", name)
		}
	}
}

func llvmTool(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	p := filepath.Join("..", "..", "..", "tinygo", "llvm-build", "bin", name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	t.Skip(name + " not found")
	return ""
}

// TestSymbols_wasm checks functions and segments tile the Code and Data
// sections, leaving only each vector count, and carry the name section's names.
func TestSymbols_wasm(t *testing.T) {
	var f File
	readFixture(t, "../../testdata/tiny.wasm", &f)
	wf, _ := f.Wasm()
	var nr xwasm.NameReader
	nr.Reset(wf, make([]byte, 64))
	funcNames := make(map[uint32]string)
	for e := range nr.FuncNames {
		name := make([]byte, e.Len)
		nr.ReadName(name, e)
		funcNames[e.Index] = string(name)
	}
	sizes := make(map[int]uint64)
	var named int
	for sym := range f.Symbols {
		sizes[sym.Section] += sym.Size
		if !sym.Func {
			continue
		}
		name := symbolName(t, &f, sym)
		if want := funcNames[uint32(sym.Index)]; name != want {
			t.Errorf("function %d named %q, want %q", sym.Index, name, want)
		}
		if name != "" {
			named++
		}
	}
	if err := f.Err(); err != nil {
		t.Fatal(err)
	}
	if named == 0 {
		t.Error("no function named")
	}
	for s := range f.Sections {
		if s.Class != ClassCode && s.Class != ClassData {
			continue
		}
		if rem := s.Size - sizes[s.Index]; rem > 5 {
			t.Errorf("section %d: symbols leave %d of %d bytes, want only the vector count", s.Index, rem, s.Size)
		}
	}
}

// TestReadName_shortBuffer checks a name buffer one byte short of a name's
// length is refused rather than filled with a truncated name.
func TestReadName_shortBuffer(t *testing.T) {
	for _, name := range fixtures {
		var f File
		readFixture(t, name, &f)
		for sym := range f.Symbols {
			n, _ := f.SymbolNameLen(sym)
			if n == 0 {
				continue
			}
			if _, err := f.ReadSymbolName(make([]byte, n-1), sym); err != io.ErrShortBuffer {
				t.Errorf("%s: name of %d bytes into %d: got %v", name, n, n-1, err)
			}
			break
		}
	}
}

// TestAllocs holds a File to its promise: once it has read a binary, reading it
// again and walking its sections and symbols, names included, allocates
// nothing, in either format.
func TestAllocs(t *testing.T) {
	var f File
	name := make([]byte, 4096)
	for _, fixture := range fixtures {
		data, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(data)
		if err := f.Read(r); err != nil {
			t.Fatal(err)
		}
		allocs := testing.AllocsPerRun(10, func() {
			if err := f.Read(r); err != nil {
				t.Fatal(err)
			}
			for s := range f.Sections {
				if _, err := f.ReadSectionName(name, s.Index); err != nil {
					t.Fatal(err)
				}
			}
			for sym := range f.Symbols {
				if _, err := f.ReadSymbolName(name, sym); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Err(); err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Errorf("%s: Read and walks allocate %v times", fixture, allocs)
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	var f File
	if err := f.Read(bytes.NewReader([]byte("MZ\x90\x00"))); err != build.ErrUnknownFormat {
		t.Errorf("PE header: got %v", err)
	}
	if f.Format() != FormatNone || f.NumSections() != 0 {
		t.Error("failed Read left a binary described")
	}
	for range f.Sections {
		t.Error("walked a section of no binary")
	}
	if f.Err() != build.ErrNotRead {
		t.Errorf("walk of no binary: got %v", f.Err())
	}
}
