package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/soypat/tinyboot/build/xelf"
)

var fixtures = []string{
	"../../testdata/blink.elf",
	"../../testdata/helloc.elf",
	"../../testdata/pca10040-blinky.elf",
}

var attributionKinds = []Kind{KindSegment, KindSection, KindSymbol, KindPackage}

// sourceKinds need DWARF line information, which every fixture carries.
var sourceKinds = []Kind{KindFile, KindLine}

func allKinds() []Kind { return append(append([]Kind{}, attributionKinds...), sourceKinds...) }

// TestAttributionKindsAgreeOnTotal is the invariant that ties the granularities
// together: whatever level you ask for, the bytes described are the same bytes.
// A section, its symbols, their packages and their source files are four views
// of one total, so any divergence means a level is dropping or double-counting.
func TestAttributionKindsAgreeOnTotal(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			// Memory mode restricts every kind to resident sections, which is
			// the footing on which the kinds are comparable.
			var want int64
			for _, kind := range append([]Kind{KindSection}, allKinds()...) {
				if kind == KindSegment {
					continue // Segments overlap sections; they are a different partition.
				}
				entries, _ := profileFixture(t, name, Flags{kind: kind, mem: true})
				_, total := Total(entries)
				if kind == KindSection {
					want = total
					continue
				}
				if total != want {
					t.Errorf("kind %v totals %d, sections total %d", kind, total, want)
				}
			}
		})
	}
}

func TestParseKind(t *testing.T) {
	for _, k := range attributionKinds {
		got, err := ParseKind(k.String())
		if err != nil {
			t.Fatalf("ParseKind(%q): %s", k, err)
		}
		if got != k {
			t.Errorf("ParseKind(%q)=%v", k, got)
		}
	}
	if _, err := ParseKind("nonsense"); err == nil {
		t.Error("ParseKind accepted an unknown kind")
	}
}

func TestPackageOf(t *testing.T) {
	for _, tc := range []struct{ sym, want string }{
		// TinyGo, package-qualified.
		{"runtime.alloc", "runtime"},
		{"internal/task.Pause", "internal/task"},
		{"machine.GetRNG", "machine"},
		{"main.main", "main"},
		// Method symbols carry a receiver in parentheses.
		{"(*internal/task.Queue).Pop", "internal/task"},
		{"(internal/task.Queue).Push", "internal/task"},
		// A package path may itself contain dots; the boundary is the first
		// dot after the last slash, not the last dot overall.
		{"github.com/soypat/tinyboot.Func", "github.com/soypat/tinyboot"},
		// Compiler-generated symbols, marked with '$'.
		{"machine$alloc.38", "machine"},
		{"runtime.run$1$gowrapper", "runtime"},
		{"internal/task$string.3", "internal/task"},
		// C symbols have no package. GCC's numeric discriminator on a
		// file-local symbol is not one either.
		{"_reset_handler", cPackage},
		{"object.0", cPackage},
		{"crlf_str.1", cPackage},
		{"SystemInit", cPackage},
		// The remainder bucket passes through so rollups still reconcile.
		{Unattributed, Unattributed},
	} {
		if got := packageOf(tc.sym); got != tc.want {
			t.Errorf("packageOf(%q)=%q want %q", tc.sym, got, tc.want)
		}
	}
}

// TestSectionProfileReconciles pins the invariant that makes the tool
// trustworthy: a file-mode section profile accounts for every byte of the file,
// including ELF headers and inter-section padding.
func TestSectionProfileReconciles(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			entries, size := profileFixture(t, name, Flags{kind: KindSection})
			_, total := Total(entries)
			if total != size {
				t.Errorf("section profile totals %d, file is %d bytes (off by %d)", total, size, total-size)
			}
		})
	}
}

// TestSymbolProfileReconciles checks that symbols plus the [unattributed]
// remainder account for each section exactly. Symbol coverage of .text runs
// 92-97% on these fixtures, so the remainder is doing real work here.
func TestSymbolProfileReconciles(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			fp, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer fp.Close()
			var f xelf.File
			if err := f.Read(fp); err != nil {
				t.Fatal(err)
			}
			entries, err := profileSymbols(&f, false)
			if err != nil {
				t.Fatal(err)
			}

			bySection := make(map[string]int64)
			for _, e := range entries {
				if e.New < 0 {
					t.Errorf("negative size %d for %q in %q", e.New, e.Name, e.Section)
				}
				bySection[e.Section] += e.New
			}
			for i := 0; i < f.NumSections(); i++ {
				s, err := f.Section(i)
				if err != nil {
					t.Fatal(err)
				}
				sh := s.SectionHeader()
				secName, err := s.Name()
				if err != nil {
					t.Fatal(err)
				}
				got, ok := bySection[secName]
				if !ok {
					continue // No symbols land here and it holds no file bytes.
				}
				want := int64(sh.SizeOnFile)
				if sh.Type == xelf.SecTypeNobits {
					want = 0
				}
				if got != want {
					t.Errorf("section %q: symbols total %d, section is %d bytes", secName, got, want)
				}
			}
		})
	}
}

// TestSelfDiffIsEmpty is the strongest invariant available without a second
// build: a binary diffed against itself must show no change anywhere.
func TestSelfDiffIsEmpty(t *testing.T) {
	for _, name := range fixtures {
		for _, kind := range allKinds() {
			t.Run(name+"/"+kind.String(), func(t *testing.T) {
				flags := Flags{kind: kind}
				entries, _ := profileFixture(t, name, flags)
				d := Diff(entries, entries)
				for _, e := range d {
					if e.Delta() != 0 {
						t.Errorf("self-diff moved %q by %d (old=%d new=%d)", e.Name, e.Delta(), e.Old, e.New)
					}
				}
				old, new := Total(d)
				if old != new {
					t.Errorf("self-diff totals differ: old=%d new=%d", old, new)
				}
				if n := len(DropUnchanged(d)); n != 0 {
					t.Errorf("self-diff left %d changed rows", n)
				}
			})
		}
	}
}

// TestCrossBuildDiffNoPanic diffs two unrelated binaries of different
// architectures. The result is semantically meaningless, but it must not panic
// or produce a total that disagrees with the two profiles it came from.
func TestCrossBuildDiffNoPanic(t *testing.T) {
	for _, kind := range allKinds() {
		t.Run(kind.String(), func(t *testing.T) {
			flags := Flags{kind: kind}
			a, _ := profileFixture(t, "../../testdata/blink.elf", flags)
			b, _ := profileFixture(t, "../../testdata/pca10040-blinky.elf", flags)
			_, wantOld := Total(a)
			_, wantNew := Total(b)

			d := Diff(a, b)
			gotOld, gotNew := Total(d)
			if gotOld != wantOld {
				t.Errorf("diff old total=%d, profile total=%d", gotOld, wantOld)
			}
			if gotNew != wantNew {
				t.Errorf("diff new total=%d, profile total=%d", gotNew, wantNew)
			}
		})
	}
}

func TestDiffAddRemoveChange(t *testing.T) {
	a := []Entry{
		{Kind: KindSymbol, Name: "kept", New: 100},
		{Kind: KindSymbol, Name: "removed", New: 50},
		{Kind: KindSymbol, Name: "grew", New: 10},
	}
	b := []Entry{
		{Kind: KindSymbol, Name: "kept", New: 100},
		{Kind: KindSymbol, Name: "added", New: 7},
		{Kind: KindSymbol, Name: "grew", New: 30},
	}
	got := make(map[string]Entry)
	for _, e := range Diff(a, b) {
		got[e.Name] = e
	}
	if e := got["kept"]; e.Delta() != 0 || e.Old != 100 || e.New != 100 {
		t.Errorf("kept: %+v", e)
	}
	if e := got["removed"]; !e.Removed() || e.Delta() != -50 {
		t.Errorf("removed: %+v", e)
	}
	if e := got["added"]; !e.Added() || e.Delta() != 7 {
		t.Errorf("added: %+v", e)
	}
	if e := got["grew"]; e.Delta() != 20 {
		t.Errorf("grew: %+v", e)
	}
}

// TestDiffDistinguishesSections guards the join key: two symbols may share a
// name across sections and must not be merged.
func TestDiffDistinguishesSections(t *testing.T) {
	a := []Entry{
		{Kind: KindSymbol, Name: "dup", Section: ".text", New: 10},
		{Kind: KindSymbol, Name: "dup", Section: ".data", New: 20},
	}
	d := Diff(a, a)
	if len(d) != 2 {
		t.Fatalf("got %d entries, want 2 (names collided across sections)", len(d))
	}
	for _, e := range d {
		if e.Delta() != 0 {
			t.Errorf("%q in %q moved by %d", e.Name, e.Section, e.Delta())
		}
	}
}

func TestSortBySize(t *testing.T) {
	es := []Entry{
		{Name: "small", Old: 0, New: 5},
		{Name: "shrank", Old: 100, New: 0},
		{Name: "grew", Old: 0, New: 40},
	}
	SortBySize(es)
	want := []string{"shrank", "grew", "small"}
	for i, w := range want {
		if es[i].Name != w {
			t.Errorf("position %d = %q, want %q", i, es[i].Name, w)
		}
	}
}

func TestFilter(t *testing.T) {
	es := []Entry{{Name: "runtime.alloc"}, {Name: "main.main"}, {Name: ".text"}}
	got, err := Filter(es, "main.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "main.main" {
		t.Errorf("Filter returned %+v", got)
	}
	// An empty pattern is a no-op, not a reject-all.
	if got, _ := Filter(es, ""); len(got) != len(es) {
		t.Errorf("empty pattern kept %d of %d", len(got), len(es))
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	entries, _ := profileFixture(t, "../../testdata/pca10040-blinky.elf", Flags{kind: KindSection})
	_, total := Total(entries)
	want := Report{
		Mode: "profile", Kind: KindSection, New: "x.elf",
		Entries: entries, Summary: Summary{New: total},
	}
	var buf bytes.Buffer
	if err := renderJSON(&buf, want); err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %s\n%s", err, buf.String())
	}
	if got.Kind != want.Kind || got.Mode != want.Mode {
		t.Errorf("header round trip: %+v", got)
	}
	if len(got.Entries) != len(want.Entries) {
		t.Fatalf("got %d entries want %d", len(got.Entries), len(want.Entries))
	}
	for i := range got.Entries {
		if got.Entries[i] != want.Entries[i] {
			t.Errorf("entry %d: got %+v want %+v", i, got.Entries[i], want.Entries[i])
		}
	}
	if got.Summary != want.Summary {
		t.Errorf("summary: got %+v want %+v", got.Summary, want.Summary)
	}
}

// TestThresholdGate covers the CI use: a diff that grows past the budget must
// report an error, and the report must still be written.
func TestThresholdGate(t *testing.T) {
	const small, big = "../../testdata/helloc.elf", "../../testdata/blink.elf"
	var buf bytes.Buffer
	err := diff(&buf, small, big, Flags{kind: KindSection, threshold: 1024})
	if err == nil {
		t.Error("growth past the threshold did not produce an error")
	}
	if buf.Len() == 0 {
		t.Error("no report written alongside the threshold failure")
	}
	// A negative threshold disables the gate.
	buf.Reset()
	if err := diff(&buf, small, big, Flags{kind: KindSection, threshold: -1}); err != nil {
		t.Errorf("gate fired while disabled: %s", err)
	}
	// Shrinking never trips the gate.
	buf.Reset()
	if err := diff(&buf, big, small, Flags{kind: KindSection, threshold: 0}); err != nil {
		t.Errorf("gate fired on a size reduction: %s", err)
	}
}

// TestFixturePairDiff exercises a diff over two builds of the same program that
// differ by one added function. See testdata/gen.sh: builds are not
// bit-reproducible (the toolchain embeds source paths in DWARF), so this
// asserts relationships rather than byte counts.
func TestFixturePairDiff(t *testing.T) {
	const a, b = "testdata/blinky-a.elf", "testdata/blinky-b.elf"
	if _, err := os.Stat(a); err != nil {
		t.Skip()
	}
	t.Run("sections grow", func(t *testing.T) {
		oldEntries, oldSize := profileFixture(t, a, Flags{kind: KindSection})
		newEntries, newSize := profileFixture(t, b, Flags{kind: KindSection})
		if newSize <= oldSize {
			t.Fatalf("fixture b (%d bytes) is not larger than a (%d)", newSize, oldSize)
		}
		sumOld, sumNew := Total(Diff(oldEntries, newEntries))
		if sumOld != oldSize || sumNew != newSize {
			t.Errorf("diff totals (%d -> %d) disagree with file sizes (%d -> %d)",
				sumOld, sumNew, oldSize, newSize)
		}
	})

	// The added code inlines into main, so main.main is where the growth lands.
	t.Run("growth attributed to main", func(t *testing.T) {
		flags := Flags{kind: KindSymbol, mem: true}
		oldEntries, _ := profileFixture(t, a, flags)
		newEntries, _ := profileFixture(t, b, flags)
		var found bool
		for _, e := range DropUnchanged(Diff(oldEntries, newEntries)) {
			if e.Name != "main.main" {
				t.Errorf("unexpected change outside main.main: %q moved %d", e.Name, e.Delta())
				continue
			}
			found = true
			if e.Delta() <= 0 {
				t.Errorf("main.main did not grow: %+v", e)
			}
		}
		if !found {
			t.Error("main.main shows no size change between the two builds")
		}
	})

	// The added code lives in main.go, so DWARF should place the growth there.
	t.Run("source attribution finds the changed file", func(t *testing.T) {
		flags := Flags{kind: KindFile, mem: true}
		oldEntries, _ := profileFixture(t, a, flags)
		newEntries, _ := profileFixture(t, b, flags)
		var grew bool
		for _, e := range DropUnchanged(Diff(oldEntries, newEntries)) {
			if e.Pos.File == "" {
				continue // The [unattributed] remainder.
			}
			if strings.HasSuffix(e.Pos.File, "main.go") && e.Delta() > 0 {
				grew = true
			}
		}
		if !grew {
			t.Error("no main.go grew between the two builds")
		}
	})

	t.Run("package rollup agrees with symbols", func(t *testing.T) {
		flags := Flags{kind: KindPackage, mem: true}
		oldEntries, _ := profileFixture(t, a, flags)
		newEntries, _ := profileFixture(t, b, flags)
		_, pkgTotal := Total(newEntries)

		symEntries, _ := profileFixture(t, b, Flags{kind: KindSymbol, mem: true})
		_, symTotal := Total(symEntries)
		if pkgTotal != symTotal {
			t.Errorf("package rollup totals %d, symbols total %d", pkgTotal, symTotal)
		}
		var mainDelta int64
		for _, e := range Diff(oldEntries, newEntries) {
			if e.Name == "main" {
				mainDelta = e.Delta()
			}
		}
		if mainDelta <= 0 {
			t.Errorf("package main did not grow, delta=%d", mainDelta)
		}
	})
}

func TestProfileTotalIgnoresTop(t *testing.T) {
	const name = "../../testdata/pca10040-blinky.elf"
	var full, trimmed bytes.Buffer
	if err := profile(&full, name, Flags{kind: KindSymbol}); err != nil {
		t.Fatal(err)
	}
	if err := profile(&trimmed, name, Flags{kind: KindSymbol, top: 3}); err != nil {
		t.Fatal(err)
	}
	// -top is a display limit; it must not change the reported total. Compare
	// the value rather than the rendered row, whose name column is sized to
	// whichever rows are on screen.
	fullTotal, trimmedTotal := totalOf(full.String()), totalOf(trimmed.String())
	if fullTotal != trimmedTotal {
		t.Errorf("-top changed the TOTAL: full=%s top3=%s", fullTotal, trimmedTotal)
	}
	if n := strings.Count(strings.TrimSpace(trimmed.String()), "\n"); n != 4 { // header + 3 rows
		t.Errorf("-top=3 produced %d body lines", n)
	}
}

// totalOf extracts the size from the trailing TOTAL row of a text report.
func totalOf(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func profileFixture(t *testing.T, name string, flags Flags) ([]Entry, int64) {
	t.Helper()
	fp, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	info, err := fp.Stat()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := profileReader(fp, info.Size(), flags)
	if err != nil {
		t.Fatal(err)
	}
	return entries, info.Size()
}
