package xwasm

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fixtures is the single TinyGo module the tests read: small, but with a host
// import, data segments, a name section and DWARF. See
// cmd/bindiff/testdata/src/gen.go.
var fixtures = []string{"../../testdata/tiny.wasm"}

func readFixture(t testing.TB, name string) (*File, []byte) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	f := new(File)
	if err := f.Read(bytes.NewReader(data)); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f, data
}

func TestRead_sectionsTileFile(t *testing.T) {
	for _, name := range fixtures {
		f, data := readFixture(t, name)
		// Sections are contiguous from the header to the end of the file.
		off := uint64(headerSize)
		for i := 0; i < f.NumSections(); i++ {
			s, _ := f.Section(i)
			sh := s.SectionHeader()
			if sh.Start != off {
				t.Fatalf("%s: section %d starts at %d, want %d", name, i, sh.Start, off)
			}
			off = sh.End()
		}
		if off != uint64(len(data)) {
			t.Fatalf("%s: sections end at %d, file is %d bytes", name, off, len(data))
		}
	}
}

func TestRead_sectionNames(t *testing.T) {
	f, _ := readFixture(t, fixtures[0])
	for _, name := range []string{"type", "import", "code", "data", "name", ".debug_line", ".debug_str", ".debug_info", "producers"} {
		s, err := f.SectionByName(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := s.Name()
		if err != nil || got != name {
			t.Fatalf("SectionByName(%q).Name() = %q, %v", name, got, err)
		}
	}
	if _, err := f.SectionByName(".debug_nonexistent"); !errors.Is(err, errNoSection) {
		t.Fatalf("want errNoSection, got %v", err)
	}
	code, _ := f.SectionByID(SecCode)
	if s, _ := f.SectionByName("code"); s != code {
		t.Fatal("SectionByName and SectionByID disagree on code")
	}
}

func TestAppendData(t *testing.T) {
	f, data := readFixture(t, fixtures[0])
	for i := 0; i < f.NumSections(); i++ {
		s, _ := f.Section(i)
		sh := s.SectionHeader()
		got, err := s.AppendData([]byte("prefix"))
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte("prefix"), data[sh.Offset:sh.End()]...)
		if !bytes.Equal(got, want) {
			t.Fatalf("section %d: AppendData mismatch", i)
		}
	}
}

// funcNames walks f's functions and joins them with their names.
func funcNames(t testing.TB, f *File) (funcs []Func, names map[uint32]string) {
	t.Helper()
	var cr CodeReader
	var nr NameReader
	if err := cr.Reset(f, make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if err := nr.Reset(f, make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	names = make(map[uint32]string)
	for idx, name := range nr.FuncNames {
		names[idx] = string(name)
	}
	if err := nr.Err(); err != nil {
		t.Fatal(err)
	}
	for fn := range cr.Funcs {
		funcs = append(funcs, fn)
	}
	if err := cr.Err(); err != nil {
		t.Fatal(err)
	}
	return funcs, names
}

func TestFuncs_tileCodeSection(t *testing.T) {
	for _, name := range fixtures {
		f, data := readFixture(t, name)
		funcs, names := funcNames(t, f)
		if len(funcs) == 0 || len(names) == 0 {
			t.Fatalf("%s: %d funcs, %d names", name, len(funcs), len(names))
		}
		code, _ := f.SectionByID(SecCode)
		sh := code.SectionHeader()
		_, countLen, _ := DecodeULEB128(data[sh.Offset:], 32)
		// Bodies follow the count back to back and end exactly at the section end.
		next := uint64(countLen)
		for _, fn := range funcs {
			if fn.Offset != next {
				t.Fatalf("%s: func %d at %d, want %d", name, fn.Index, fn.Offset, next)
			}
			next = fn.End()
		}
		if next != sh.Size {
			t.Fatalf("%s: bodies end at %d, code section is %d", name, next, sh.Size)
		}
	}
}

// TestFuncs_matchesLLVM cross-checks function placement and naming against
// llvm-nm, which reports a function's address as the file offset of its size
// prefix.
func TestFuncs_matchesLLVM(t *testing.T) {
	nm := llvmTool(t, "llvm-nm")
	for _, name := range fixtures {
		f, _ := readFixture(t, name)
		funcs, names := funcNames(t, f)
		code, _ := f.SectionByID(SecCode)
		base := code.SectionHeader().Offset

		out, err := exec.Command(nm, name).Output()
		if err != nil {
			t.Fatal(err)
		}
		want := make(map[string]uint64)
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			fields := strings.SplitN(sc.Text(), " ", 3)
			if len(fields) != 3 || (fields[1] != "t" && fields[1] != "T") {
				continue
			}
			addr, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			want[fields[2]] = addr
		}
		var matched int
		for _, fn := range funcs {
			fnName, ok := names[fn.Index]
			if !ok {
				continue
			}
			addr, ok := want[fnName]
			if !ok {
				t.Errorf("%s: %s not in llvm-nm output", name, fnName)
				continue
			}
			if got := base + fn.Offset; got != addr {
				t.Errorf("%s: %s at %#x, llvm-nm says %#x", name, fnName, got, addr)
			}
			matched++
		}
		if matched != len(want) {
			t.Errorf("%s: matched %d functions, llvm-nm lists %d", name, matched, len(want))
		}
	}
}

// llvmTool finds an LLVM tool on PATH or in a sibling TinyGo checkout, and
// skips the test if there is none.
func llvmTool(t *testing.T, name string) string {
	t.Helper()
	p := llvmToolOptional(name)
	if p == "" {
		t.Skip(name + " not found")
	}
	return p
}

func TestNameReader_bufferTooSmall(t *testing.T) {
	f, _ := readFixture(t, fixtures[0])
	var nr NameReader
	if err := nr.Reset(f, make([]byte, maxSectionFrame)); err != nil {
		t.Fatal(err)
	}
	for range nr.FuncNames {
	}
	var small BufferTooSmallError
	if !errors.As(nr.Err(), &small) || small.Need <= small.Have {
		t.Fatalf("want BufferTooSmallError, got %v", nr.Err())
	}
	// Growing to what was asked for gets past that name.
	if err := nr.Reset(f, make([]byte, small.Need)); err != nil {
		t.Fatal(err)
	}
	var n int
	for range nr.FuncNames {
		n++
	}
	if n == 0 {
		t.Fatal("no names after growing buffer")
	}
}

// A caller breaking out of one name walk must not narrow the next: the name
// map bounds the cursor by its subsection while it walks, and that bound has to
// come off however the walk ends.
func TestNameReader_earlyStop(t *testing.T) {
	f, _ := readFixture(t, fixtures[0])
	var nr NameReader
	if err := nr.Reset(f, make([]byte, 256)); err != nil {
		t.Fatal(err)
	}
	var want int
	for range nr.DataNames {
		want++
	}
	if nr.Err() != nil || want == 0 {
		t.Fatal("fixture has no data names:", nr.Err())
	}
	for range nr.FuncNames {
		break
	}
	var got int
	for range nr.DataNames {
		got++
	}
	if nr.Err() != nil || got != want {
		t.Fatalf("after early stop got %d data names, want %d (err %v)", got, want, nr.Err())
	}
}

func TestAllocs(t *testing.T) {
	data, err := os.ReadFile(fixtures[0])
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(data)
	var f File
	var cr CodeReader
	var nr NameReader
	var dr DataReader
	cbuf, nbuf, dbuf := make([]byte, 64), make([]byte, 256), make([]byte, 64)
	walk := func() {
		if err := f.Read(r); err != nil {
			t.Fatal(err)
		}
		if err := cr.Reset(&f, cbuf); err != nil {
			t.Fatal(err)
		}
		if err := nr.Reset(&f, nbuf); err != nil {
			t.Fatal(err)
		}
		for range cr.Funcs {
		}
		for range nr.FuncNames {
		}
		for range nr.DataNames {
		}
		if err := dr.Reset(&f, dbuf); err != nil {
			t.Fatal(err)
		}
		for range dr.Segments {
		}
		if cr.Err() != nil || nr.Err() != nil || dr.Err() != nil {
			t.Fatal(cr.Err(), nr.Err(), dr.Err())
		}
		if _, err := f.SectionByName(".debug_line"); err != nil {
			t.Fatal(err)
		}
	}
	walk() // Grow the section table.
	if allocs := testing.AllocsPerRun(10, walk); allocs != 0 {
		t.Fatalf("walk allocates %v times, want 0", allocs)
	}
}

func TestReadRejects(t *testing.T) {
	good, err := os.ReadFile(fixtures[0])
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte("\x00asm\x01\x00\x00\x00")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short header", hdr[:5]},
		{"bad magic", []byte("\x7fELF\x01\x00\x00\x00")},
		{"bad version", []byte("\x00asm\x02\x00\x00\x00")},
		{"unknown section id", append(hdr[:8:8], 14, 0)},
		{"section past EOF", append(hdr[:8:8], 1, 5, 0)},
		{"out of order", append(hdr[:8:8], 3, 0, 1, 0)},
		{"duplicate", append(hdr[:8:8], 1, 0, 1, 0)},
		{"custom name exceeds section", append(hdr[:8:8], 0, 1, 5)},
		{"overlong size LEB", append(hdr[:8:8], 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0)},
		{"truncated", good[:len(good)-1]},
	} {
		var f File
		if err := f.Read(bytes.NewReader(tc.data)); err == nil {
			t.Errorf("%s: no error", tc.name)
		} else if f.NumSections() != 0 {
			t.Errorf("%s: failed Read left %d sections", tc.name, f.NumSections())
		}
	}
	// Tag sorts between memory and global despite its id, and datacount
	// between element and code.
	var f File
	ordered := append(hdr[:8:8], 5, 0, 13, 0, 6, 0, 9, 0, 12, 0, 10, 0)
	if err := f.Read(bytes.NewReader(ordered)); err != nil {
		t.Fatal("spec section order rejected:", err)
	}
	// A header-only module is valid and empty.
	if err := f.Read(bytes.NewReader(hdr)); err != nil || f.NumSections() != 0 {
		t.Fatal("empty module:", err, f.NumSections())
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	var b [headerSize]byte
	n, err := Header{Version: 1}.Put(b[:])
	if err != nil || n != headerSize {
		t.Fatal(n, err)
	}
	h, n, err := DecodeHeader(b[:])
	if err != nil || n != headerSize || h.Version != 1 {
		t.Fatal(h, n, err)
	}
}

func TestDecodeULEB128(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		bits int
		v    uint64
		n    int
		err  error
	}{
		{[]byte{0}, 32, 0, 1, nil},
		{[]byte{0x7f}, 32, 127, 1, nil},
		{[]byte{0x80, 0x01}, 32, 128, 2, nil},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 32, 1<<32 - 1, 5, nil},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x00}, 32, 0, 5, nil}, // Padded zero is legal.
		{[]byte{0xff, 0xff, 0xff, 0xff, 0x1f}, 32, 0, 5, errLEBOverflow},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 32, 0, 5, errLEBOverflow},
		{[]byte{0x80}, 32, 0, 1, io.ErrUnexpectedEOF},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, 64, 1<<64 - 1, 10, nil},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, 64, 0, 10, errLEBOverflow},
		{[]byte{0x7f}, 7, 127, 1, nil},
		{[]byte{0x80, 0x00}, 7, 0, 1, errLEBTooLong},
	} {
		v, n, err := DecodeULEB128(tc.b, tc.bits)
		if v != tc.v || n != tc.n || err != tc.err {
			t.Errorf("DecodeULEB128(%x, %d) = %d, %d, %v; want %d, %d, %v", tc.b, tc.bits, v, n, err, tc.v, tc.n, tc.err)
		}
		// The streaming decoder agrees on value and validity.
		var c cursor
		c.reset(bytes.NewReader(tc.b), make([]byte, 16), 0, int64(len(tc.b)))
		sv := c.uleb(tc.bits)
		if (c.err == nil) != (tc.err == nil) || sv != tc.v {
			t.Errorf("cursor.uleb(%x, %d) = %d, %v; want %d, %v", tc.b, tc.bits, sv, c.err, tc.v, tc.err)
		}
	}
}

func TestDecodeSLEB128(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		bits int
		v    int64
		n    int
		err  error
	}{
		{[]byte{0}, 32, 0, 1, nil},
		{[]byte{0x7f}, 32, -1, 1, nil},
		{[]byte{0x3f}, 32, 63, 1, nil},
		{[]byte{0x40}, 32, -64, 1, nil},
		{[]byte{0x80, 0x7f}, 32, -128, 2, nil},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0x07}, 32, 1<<31 - 1, 5, nil},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x78}, 32, -1 << 31, 5, nil},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 32, 0, 5, errLEBOverflow}, // 2^32-1 as s32.
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x70}, 32, 0, 5, errLEBOverflow},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x80}, 32, 0, 5, errLEBTooLong},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x70}, 33, -1 << 32, 5, nil},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x7f}, 33, -1 << 28, 5, nil},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x60}, 33, 0, 5, errLEBOverflow},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}, 64, -1 << 63, 10, nil},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, 64, 1<<63 - 1, 10, nil},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 64, 0, 10, errLEBOverflow},
		{[]byte{0xc0}, 32, 0, 1, io.ErrUnexpectedEOF},
	} {
		v, n, err := DecodeSLEB128(tc.b, tc.bits)
		if v != tc.v || n != tc.n || err != tc.err {
			t.Errorf("DecodeSLEB128(%x, %d) = %d, %d, %v; want %d, %d, %v", tc.b, tc.bits, v, n, err, tc.v, tc.n, tc.err)
		}
		var c cursor
		c.reset(bytes.NewReader(tc.b), make([]byte, 16), 0, int64(len(tc.b)))
		sv := c.sleb(tc.bits)
		if (c.err == nil) != (tc.err == nil) || sv != tc.v {
			t.Errorf("cursor.sleb(%x, %d) = %d, %v; want %d, %v", tc.b, tc.bits, sv, c.err, tc.v, tc.err)
		}
	}
}

func TestDataSegments(t *testing.T) {
	for _, name := range fixtures {
		f, data := readFixture(t, name)
		var dr DataReader
		var nr NameReader
		if err := dr.Reset(f, make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		if err := nr.Reset(f, make([]byte, 256)); err != nil {
			t.Fatal(err)
		}
		names := make(map[uint32]string)
		for idx, n := range nr.DataNames {
			names[idx] = string(n)
		}
		if nr.Err() != nil {
			t.Fatal(nr.Err())
		}
		sec, _ := f.SectionByID(SecData)
		sh := sec.SectionHeader()
		_, countLen, _ := DecodeULEB128(data[sh.Offset:], 32)
		next := uint64(countLen)
		addrs := make(map[string]uint64)
		for seg := range dr.Segments {
			if seg.Offset != next {
				t.Fatalf("%s: segment %d at %d, want %d", name, seg.Index, seg.Offset, next)
			}
			next = seg.End()
			if !seg.AddrKnown {
				t.Errorf("%s: segment %d has no constant address", name, seg.Index)
			}
			addrs[names[seg.Index]] = seg.Addr
		}
		if dr.Err() != nil {
			t.Fatal(dr.Err())
		}
		if next != sh.Size {
			t.Fatalf("%s: segments end at %d, data section is %d", name, next, sh.Size)
		}
		// wasm-ld names segments after their output sections, and llvm-nm
		// reports each at its linear-memory address.
		for _, seg := range []string{".rodata", ".data"} {
			if _, ok := addrs[seg]; !ok {
				t.Errorf("%s: no %s segment among %v", name, seg, names)
			}
		}
		nm := llvmToolOptional("llvm-nm")
		if nm == "" {
			continue
		}
		out, err := exec.Command(nm, name).Output()
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			fields := strings.SplitN(sc.Text(), " ", 3)
			if len(fields) != 3 || fields[1] != "d" {
				continue
			}
			want, _ := strconv.ParseUint(fields[0], 16, 64)
			if got, ok := addrs[fields[2]]; ok && got != want {
				t.Errorf("%s: segment %s at %#x, llvm-nm says %#x", name, fields[2], got, want)
			}
		}
	}
}

func TestConstExpr(t *testing.T) {
	for _, tc := range []struct {
		expr  []byte
		v     uint64
		known bool
		fail  bool
	}{
		{[]byte{opI32Const, 0x80, 0x80, 0x04, opEnd}, 0x10000, true, false},
		{[]byte{opI32Const, 0x7f, opEnd}, 0xffffffff, true, false}, // -1 as an i32 address.
		{[]byte{opI64Const, 0x10, opEnd}, 16, true, false},
		{[]byte{opGlobalGet, 0x01, opEnd}, 0, false, false},
		// Extended-const arithmetic is skipped, not evaluated.
		{[]byte{opGlobalGet, 0x00, opI32Const, 0x10, opI32Add, opEnd}, 0, false, false},
		{[]byte{opPrefixSIMD, simdV128Const, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, opEnd}, 0, false, false},
		{[]byte{0x20, 0x00, opEnd}, 0, false, true}, // local.get is not constant.
		{[]byte{opI32Const, 0x10}, 0, false, true},  // Missing end.
	} {
		var c cursor
		c.reset(bytes.NewReader(tc.expr), make([]byte, 32), 0, int64(len(tc.expr)))
		v, known := c.constExpr()
		if (c.err != nil) != tc.fail || v != tc.v || known != tc.known {
			t.Errorf("constExpr(%x) = %d, %v, %v; want %d, %v, fail=%v", tc.expr, v, known, c.err, tc.v, tc.known, tc.fail)
		}
	}
}

func llvmToolOptional(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	p := filepath.Join("..", "..", "..", "tinygo", "llvm-build", "bin", name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}
