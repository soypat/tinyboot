package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var wasmFixtures = []string{
	"../../testdata/hello.wasm",
	"../../testdata/hello-nodebug.wasm",
}

// wasmDebugFixture is the module carrying DWARF, which the source kinds need.
const wasmDebugFixture = "../../testdata/hello.wasm"

var wasmKinds = []Kind{KindSection, KindSymbol, KindPackage, KindFile, KindLine}

func wasmKindsFor(name string) []Kind {
	if name == wasmDebugFixture {
		return wasmKinds
	}
	return wasmKinds[:3]
}

// TestWasmSectionProfileReconciles is TestSectionProfileReconciles for a
// module: sections plus their framing account for every byte of the file.
func TestWasmSectionProfileReconciles(t *testing.T) {
	for _, name := range wasmFixtures {
		entries, size := profileFixture(t, name, Flags{kind: KindSection})
		_, total := Total(entries)
		if total != size {
			t.Errorf("%s: section profile totals %d, file is %d bytes", name, total, size)
		}
		for _, e := range entries {
			if e.Name == Unattributed {
				t.Errorf("%s: %d bytes no section claims", name, e.New)
			}
		}
	}
}

// TestWasmKindsAgreeOnTotal: every kind below section describes the same bytes,
// the section contents, which is the section total less the framing.
func TestWasmKindsAgreeOnTotal(t *testing.T) {
	for _, name := range wasmFixtures {
		sections, _ := profileFixture(t, name, Flags{kind: KindSection})
		var want int64
		for _, e := range sections {
			if e.Name != "[wasm-headers]" {
				want += e.New
			}
		}
		for _, kind := range wasmKindsFor(name)[1:] {
			entries, _ := profileFixture(t, name, Flags{kind: kind})
			if _, total := Total(entries); total != want {
				t.Errorf("%s: kind %v totals %d, section contents total %d", name, kind, total, want)
			}
		}
	}
}

// TestWasmSymbolProfileReconciles checks each section's symbols plus remainder
// against the section, and that functions leave only the Code section's
// leading count unattributed.
func TestWasmSymbolProfileReconciles(t *testing.T) {
	for _, name := range wasmFixtures {
		sections, _ := profileFixture(t, name, Flags{kind: KindSection})
		entries, _ := profileFixture(t, name, Flags{kind: KindSymbol})
		bySection := make(map[string]int64)
		for _, e := range entries {
			if e.New < 0 {
				t.Errorf("%s: negative size %d for %q", name, e.New, e.Name)
			}
			bySection[e.Section] += e.New
			if e.Name == Unattributed && (e.Section == "code" || e.Section == "data") && e.New > 5 {
				t.Errorf("%s: %d bytes of %s unattributed, want only the vector count", name, e.New, e.Section)
			}
		}
		for _, s := range sections {
			if s.Name == "[wasm-headers]" {
				continue
			}
			if got := bySection[s.Name]; got != s.New {
				t.Errorf("%s: section %q: symbols total %d, section is %d bytes", name, s.Name, got, s.New)
			}
		}
		var hasStart bool
		for _, e := range entries {
			hasStart = hasStart || e.Name == "_start"
		}
		if !hasStart {
			t.Errorf("%s: no _start among function symbols", name)
		}
	}
}

// TestWasmSelfDiffIsEmpty mirrors TestSelfDiffIsEmpty.
func TestWasmSelfDiffIsEmpty(t *testing.T) {
	for _, name := range wasmFixtures {
		for _, kind := range wasmKindsFor(name) {
			entries, _ := profileFixture(t, name, Flags{kind: kind})
			if n := len(DropUnchanged(Diff(entries, entries))); n != 0 {
				t.Errorf("%s/%v: self-diff left %d changed rows", name, kind, n)
			}
		}
	}
}

// TestWasmCrossBuildDiff diffs the debug build against the -no-debug one.
// TinyGo's -no-debug also changes code generation, so the builds genuinely
// differ; what must hold is that the diff's sides are exactly the two profiles.
func TestWasmCrossBuildDiff(t *testing.T) {
	for _, kind := range wasmKinds[:3] {
		flags := Flags{kind: kind}
		a, _ := profileFixture(t, wasmFixtures[0], flags)
		b, _ := profileFixture(t, wasmFixtures[1], flags)
		_, wantOld := Total(a)
		_, wantNew := Total(b)
		old, new := Total(Diff(a, b))
		if old != wantOld || new != wantNew {
			t.Errorf("%v: diff totals old=%d new=%d, profiles total %d and %d", kind, old, new, wantOld, wantNew)
		}
	}
}

func TestWasmUnsupported(t *testing.T) {
	for _, flags := range []Flags{
		{kind: KindSegment},
		{kind: KindSection, mem: true},
	} {
		fp, err := os.Open(wasmDebugFixture)
		if err != nil {
			t.Fatal(err)
		}
		_, err = profileReader(fp, 0, flags)
		fp.Close()
		if err == nil {
			t.Errorf("%+v: no error", flags)
		}
	}
	fp, err := os.Open(wasmFixtures[1])
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	if _, err := profileReader(fp, 0, Flags{kind: KindFile}); !errors.Is(err, errWasmNoDebugLine) {
		t.Errorf("module without DWARF: got %v, want %v", err, errWasmNoDebugLine)
	}
}

// TestWasmLineCoverageMatchesLLVM checks the source kinds attribute exactly the
// code bytes llvm-dwarfdump's line table covers: each row runs to the next row
// of its sequence.
func TestWasmLineCoverageMatchesLLVM(t *testing.T) {
	dump := llvmTool(t, "llvm-dwarfdump")
	out, err := exec.Command(dump, "--debug-line", wasmDebugFixture).Output()
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
	entries, _ := profileFixture(t, wasmDebugFixture, Flags{kind: KindFile})
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
