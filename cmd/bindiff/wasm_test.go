package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/soypat/tinyboot/build"
	"github.com/soypat/tinyboot/build/xwasm"
)

// wasmFixture is the one WebAssembly module the tests read, a TinyGo build
// with DWARF. See testdata/src/gen.go. What the fixture cannot exercise --
// a module without DWARF, a gc-built one -- is built in memory instead.
const wasmFixture = "../../testdata/tiny.wasm"

var wasmKinds = []Kind{KindSection, KindSymbol, KindPackage, KindFile, KindLine}

// TestWasmProfiles holds the invariants that make a report trustworthy, over
// every kind that applies to a module:
//   - sections plus their framing account for every byte of the file;
//   - every kind below section describes the section contents, no more or less;
//   - symbols tile the code and data sections, leaving only each vector count;
//   - a profile diffed against itself changes nothing.
func TestWasmProfiles(t *testing.T) {
	sections, size := profileFixture(t, wasmFixture, Flags{kind: KindSection})
	var contents int64
	sectionSize := make(map[string]int64)
	for _, e := range sections {
		switch e.Name {
		case Unattributed:
			t.Errorf("%d bytes no section claims", e.New)
		case "[wasm-headers]":
		default:
			contents += e.New
			sectionSize[e.Name] = e.New
		}
	}
	if _, total := Total(sections); total != size {
		t.Errorf("section profile totals %d, file is %d bytes", total, size)
	}

	for _, kind := range wasmKinds {
		entries, _ := profileFixture(t, wasmFixture, Flags{kind: kind})
		if kind != KindSection {
			if _, total := Total(entries); total != contents {
				t.Errorf("kind %v totals %d, section contents total %d", kind, total, contents)
			}
		}
		if n := len(DropUnchanged(Diff(entries, entries))); n != 0 {
			t.Errorf("kind %v: self-diff left %d changed rows", kind, n)
		}
		if kind != KindSymbol {
			continue
		}
		bySection := make(map[string]int64)
		var hasMain bool
		for _, e := range entries {
			bySection[e.Section] += e.New
			hasMain = hasMain || strings.HasPrefix(e.Name, "main.")
			if e.Name == Unattributed && (e.Section == "code" || e.Section == "data") && e.New > 5 {
				t.Errorf("%d bytes of %s unattributed, want only the vector count", e.New, e.Section)
			}
		}
		for name, want := range sectionSize {
			if got := bySection[name]; got != want {
				t.Errorf("section %q: symbols total %d, section is %d bytes", name, got, want)
			}
		}
		if !hasMain {
			t.Error("no main function among symbols")
		}
	}
}

// TestWasmLineCoverageMatchesLLVM checks the source kinds attribute exactly the
// code bytes llvm-dwarfdump's line table covers: each row runs to the next row
// of its sequence.
func TestWasmLineCoverageMatchesLLVM(t *testing.T) {
	dump := llvmTool(t, "llvm-dwarfdump")
	out, err := exec.Command(dump, "--debug-line", wasmFixture).Output()
	if err != nil {
		t.Fatal(err)
	}
	var want, prev uint64
	var open bool
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "0x") || len(line) < 18 || line[18] != ' ' {
			continue // Not a row of the line matrix.
		}
		addr, err := strconv.ParseUint(line[2:18], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if open && addr > prev {
			want += addr - prev
		}
		prev, open = addr, !strings.Contains(line, "end_sequence")
	}
	if want == 0 {
		t.Fatal("parsed no line table coverage from llvm-dwarfdump")
	}
	entries, _ := profileFixture(t, wasmFixture, Flags{kind: KindFile})
	var got int64
	for _, e := range entries {
		if e.Name != Unattributed {
			got += e.New
		}
	}
	if uint64(got) != want {
		t.Errorf("file kind attributes %d code bytes, llvm-dwarfdump's line table covers %d", got, want)
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

// wasmModule builds a module from the preamble and the given custom sections,
// each a name and payload.
func wasmModule(custom ...string) []byte {
	b := []byte("\x00asm\x01\x00\x00\x00")
	for i := 0; i+1 < len(custom); i += 2 {
		name, payload := custom[i], custom[i+1]
		// Lengths here stay under 128, so each LEB128 is one byte.
		b = append(b, 0, byte(1+len(name)+len(payload)), byte(len(name)))
		b = append(b, name...)
		b = append(b, payload...)
	}
	return b
}

func TestWasmUnsupported(t *testing.T) {
	fixture, err := os.ReadFile(wasmFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []Flags{
		{kind: KindSegment},
		{kind: KindSection, mem: true},
	} {
		if _, err := profileReader(bytes.NewReader(fixture), 0, flags); err == nil {
			t.Errorf("%+v: no error", flags)
		}
	}
	_, err = profileReader(bytes.NewReader(wasmModule()), 0, Flags{kind: KindFile})
	if err != build.ErrNoDebugLine {
		t.Errorf("module without DWARF: got %v, want %v", err, build.ErrNoDebugLine)
	}
}

func TestIsGcWasm(t *testing.T) {
	fixture, err := os.ReadFile(wasmFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		module []byte
		want   bool
	}{
		{"tinygo fixture", fixture, false},
		{"go:buildid", wasmModule("go:buildid", "abc/def"), true},
		{"producers", wasmModule("producers", "\x01\x0cprocessed-by\x01\x0eGo cmd/compile\x08go1.26.3"), true},
		{"empty", wasmModule(), false},
	} {
		var f xwasm.File
		if err := f.Read(bytes.NewReader(tc.module)); err != nil {
			t.Fatal(tc.name, err)
		}
		if got := isGcWasm(&f); got != tc.want {
			t.Errorf("%s: isGcWasm=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestGcWasmPackageOf(t *testing.T) {
	for _, tc := range []struct{ sym, want string }{
		// Single-element paths: the first dot ends the package.
		{"runtime.alloc", "runtime"},
		{"time.__Duration_.Truncate", "time"},
		{"runtime.alloc_m.func1", "runtime"}, // '_' after the dot is the identifier's.
		// '/' arrives as '_'; the first dot after it ends the path.
		{"github.com_google_gopacket_layers.init", "github.com_google_gopacket_layers"},
		{"golang.zx2c4.com_wireguard_device.__Device_.Up", "golang.zx2c4.com_wireguard_device"},
		{"crypto_internal_fips140_nistec_fiat.p521Mul", "crypto_internal_fips140_nistec_fiat"},
		// The last element's dots are escaped as %2e, arriving as _2e.
		{"gopkg.in_yaml_2ev3.yaml_emitter_write_double_quoted_scalar", "gopkg.in_yaml_2ev3"},
		{"_rt0_wasm_wasip1", cPackage},
		{"[data 99997]", "[data]"},
	} {
		if got := gcWasmPackageOf(tc.sym); got != tc.want {
			t.Errorf("gcWasmPackageOf(%q)=%q want %q", tc.sym, got, tc.want)
		}
	}
}

// TestGcWasmLocalModule checks a large gc-built module when one is present in
// the untracked local directory.
func TestGcWasmLocalModule(t *testing.T) {
	const name = "../../local/netbird.wasm"
	if _, err := os.Stat(name); err != nil {
		t.Skip("no local module")
	}
	entries, _ := profileFixture(t, name, Flags{kind: KindPackage})
	for _, e := range entries {
		switch e.Name {
		case "github", "golang", "google", "gopkg", "[type]":
			t.Errorf("package %q (%d bytes): mangled names split at the wrong dot", e.Name, e.New)
		}
	}
}
