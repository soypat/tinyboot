package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/soypat/tinyboot/build/xobj"
)

// placement is one symbol's claim on a range of a section, after overlapping
// claims have been resolved.
type placement struct {
	name    string
	section string
	addr    uint64 // Clamped start address.
	size    int64  // Clamped size; zero for a symbol wholly covered by another.
	// inLines marks an address in the space the DWARF line table describes. An
	// ELF binary has one address space for everything it loads. A WebAssembly
	// module does not: line addresses are Code section offsets, and a data
	// segment's offset in its own section would alias them.
	inLines bool
}

// tiling is the result of dividing a binary's sections among its symbols.
type tiling struct {
	placements []placement
	// remainder holds, per section, the bytes no symbol accounted for.
	remainder map[string]int64
	// order preserves section order for deterministic output.
	order []string
}

// claim is one symbol's stake in a section, before overlapping claims are
// resolved.
type claim struct {
	name        string
	start, size uint64
}

func newTiling(nsect, nsyms int) tiling {
	return tiling{
		placements: make([]placement, 0, nsyms),
		remainder:  make(map[string]int64, nsect),
		order:      make([]string, 0, nsect),
	}
}

// tileSection divides a section of size bytes among claims and records what
// they leave over. A section with no claims and no bytes is left out.
func (t *tiling) tileSection(section string, size int64, claims []claim, inLines bool) {
	if len(claims) == 0 {
		if size > 0 {
			t.order = append(t.order, section)
			t.remainder[section] = size
		}
		return
	}
	t.order = append(t.order, section)
	// Tile the section in address order, clamping each symbol so that
	// overlapping symbols -- weak aliases and ifunc pairs share an address --
	// are counted once. Without this, a section's symbols can sum past its own
	// size and drive the remainder negative.
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].start != claims[j].start {
			return claims[i].start < claims[j].start
		}
		return claims[i].size > claims[j].size
	})
	var cursor uint64
	var attributed int64
	for i, p := range claims {
		if i == 0 {
			cursor = p.start
		}
		start, end := p.start, p.start+p.size
		if start < cursor {
			start = cursor
		}
		var size int64
		if end > start {
			size = int64(end - start)
			cursor = end
		}
		attributed += size
		t.placements = append(t.placements, placement{
			name:    p.name,
			section: section,
			addr:    start,
			size:    size,
			inLines: inLines,
		})
	}
	t.remainder[section] = size - attributed
}

// profileSymbols attributes bytes to individual functions and data objects.
//
// Symbols do not tile their section perfectly: on the repo's fixtures .text is
// 92-97% covered, the rest being alignment padding, compiler-emitted stubs and
// symbols whose st_size is zero. The shortfall per section is reported as
// [unattributed] so the rows still sum to the section size.
func profileSymbols(f *xobj.File, mem bool) ([]Entry, error) {
	t, err := tileSymbols(f, mem)
	if err != nil {
		return nil, err
	}
	return symbolEntries(t), nil
}

// symbolEntries lists a tiling's placements, then each section's remainder.
func symbolEntries(t tiling) []Entry {
	entries := make([]Entry, 0, len(t.placements)+len(t.order))
	for _, p := range t.placements {
		entries = append(entries, Entry{
			Kind:    KindSymbol,
			Name:    p.name,
			Section: p.section,
			Pos:     Pos{Addr: p.addr},
			New:     p.size,
		})
	}
	for _, sec := range t.order {
		if rem := t.remainder[sec]; rem != 0 {
			entries = append(entries, Entry{
				Kind: KindSymbol, Name: Unattributed, Section: sec, New: rem,
			})
		}
	}
	return entries
}

// tileSymbols divides each section's bytes among the symbols that land in it.
// Placements carry line-table addresses: an ELF symbol's value, a WebAssembly
// function's offset in the Code section.
func tileSymbols(f *xobj.File, mem bool) (tiling, error) {
	// Resolve sections once; symbols reference them by index.
	type section struct {
		name     string
		size     int64 // Negative for a section left out of a memory profile.
		inLines  bool
		lineBase uint64
	}
	var names nameBuf
	sections := make([]section, f.NumSections())
	for s := range f.Sections {
		name, err := names.section(f, s.Index)
		if err != nil {
			return tiling{}, err
		}
		sec := section{name: name, size: int64(s.Size), inLines: s.InLines, lineBase: s.LineBase}
		if mem {
			sec.size = int64(s.MemSize)
			if !s.Loaded {
				sec.size = -1 // Not resident.
			}
		}
		sections[s.Index] = sec
	}
	if err := f.Err(); err != nil {
		return tiling{}, err
	}

	// Bucket symbols by section so each section can be tiled independently.
	bySection := make([][]claim, len(sections))
	var nsyms int
	for sym := range f.Symbols {
		sec := &sections[sym.Section]
		if sec.size <= 0 {
			continue
		}
		name, err := names.symbol(f, sym)
		if err != nil {
			return tiling{}, fmt.Errorf("symbols: %w", err)
		}
		bySection[sym.Section] = append(bySection[sym.Section], claim{
			name:  name,
			start: sec.lineBase + sym.Off,
			size:  sym.Size,
		})
		nsyms++
	}
	if err := f.Err(); err != nil {
		return tiling{}, fmt.Errorf("symbols: %w", err)
	}

	t := newTiling(len(sections), nsyms)
	for i, sec := range sections {
		t.tileSection(sec.name, sec.size, bySection[i], sec.inLines)
	}
	return t, nil
}

// nameBuf reads names through one buffer, grown to the longest name read.
type nameBuf []byte

// grow makes the buffer at least n bytes long.
func (nb *nameBuf) grow(n int) {
	if n > len(*nb) {
		*nb = make([]byte, max(n, 2*len(*nb)))
	}
}

// Names are read straight into the buffer, and their length asked for only
// when it turns out too short. Asking first would cost an ELF name a second
// read of its string table every time, where the buffer soon fits them all.

func (nb *nameBuf) section(f *xobj.File, i int) (string, error) {
	n, err := f.ReadSectionName(*nb, i)
	if err == io.ErrShortBuffer {
		if n, err = f.SectionNameLen(i); err == nil {
			nb.grow(n)
			n, err = f.ReadSectionName(*nb, i)
		}
	}
	if err != nil {
		return "", err
	}
	return string((*nb)[:n]), nil
}

// symbol returns a symbol's name, or for one the binary leaves unnamed a
// placeholder naming its index space: "[func 12]", "[data 7]". Placeholders are
// bracketed, like bindiff's other synthetic names, so [packageOf] can tell them
// from symbols. The gc toolchain names no WebAssembly data segments at all, so
// on its modules every segment is one of these.
func (nb *nameBuf) symbol(f *xobj.File, sym xobj.Symbol) (string, error) {
	n, err := f.ReadSymbolName(*nb, sym)
	if err == io.ErrShortBuffer {
		if n, err = f.SymbolNameLen(sym); err == nil {
			nb.grow(n)
			n, err = f.ReadSymbolName(*nb, sym)
		}
	}
	if err != nil {
		return "", err
	}
	if n == 0 {
		space := "data"
		if sym.Func {
			space = "func"
		}
		return fmt.Sprintf("[%s %d]", space, sym.Index), nil
	}
	return string((*nb)[:n]), nil
}

// profilePackages rolls a symbol profile up by the package each symbol belongs
// to. TinyGo emits fully package-qualified symbol names, so this needs no debug
// information; C symbols have no package and collect under [c].
func profilePackages(f *xobj.File, mem bool) ([]Entry, error) {
	syms, err := profileSymbols(f, mem)
	if err != nil {
		return nil, err
	}
	pkgOf := packageOf
	if w, ok := f.Wasm(); ok && isGcWasm(w) {
		pkgOf = gcWasmPackageOf
	}
	return packageEntries(syms, pkgOf), nil
}

// packageEntries rolls symbol entries up by package.
func packageEntries(syms []Entry, pkgOf func(sym string) string) []Entry {
	order := make([]string, 0, 32)
	byPkg := make(map[string]*Entry, 32)
	for _, e := range syms {
		name := pkgOf(e.Name)
		agg, ok := byPkg[name]
		if !ok {
			order = append(order, name)
			byPkg[name] = &Entry{Kind: KindPackage, Name: name}
			agg = byPkg[name]
		}
		agg.New += e.New
	}
	entries := make([]Entry, 0, len(order))
	for _, name := range order {
		entries = append(entries, *byPkg[name])
	}
	return entries
}

// Buckets for symbols that name no package of their own.
const (
	// cPackage collects symbols that carry no package qualifier.
	cPackage = "[c]"
	// typePackage collects type descriptors: reflect metadata a compiler names
	// by spelling the type out, which belongs to no package at all.
	typePackage = "[type]"
)

// typePunct are the characters that begin a spelled-out type in a symbol name
// and can appear in no package path or identifier.
const typePunct = ":{}[](),; "

// packageOf extracts the package path from a symbol name.
//
// A package path may itself contain dots ("github.com/soypat/x.Func"), so the
// boundary is the first dot after the final slash rather than the last dot.
func packageOf(sym string) string {
	if pkg, ok := bucketOf(sym); ok {
		return pkg
	}
	s := sym
	// The gc linker names its own generated symbols with a colon and no
	// package: go:func.*, go:string.*, go:itab.*, type:*. Report them under
	// that prefix rather than letting what follows drive the split.
	if head, rest, ok := strings.Cut(s, ":"); ok && (head == "go" || head == "type") {
		if d := strings.Index(rest, "."); d >= 0 {
			return head + ":" + rest[:d]
		}
		return head
	}
	// Method symbols carry a receiver: "(*internal/task.Queue).Pop".
	if strings.HasPrefix(s, "(") {
		if end := strings.Index(s, ")"); end > 1 {
			s = strings.TrimPrefix(s[1:end], "*")
		}
	}
	// TinyGo marks compiler-generated symbols with '$'. Everything before the
	// first one is package-qualified, as in "machine$alloc.38" (package
	// "machine") or "runtime.run$1$gowrapper" (package "runtime").
	generated := false
	if i := strings.Index(s, "$"); i >= 0 {
		s, generated = s[:i], true
	}
	// Cut off any spelled-out type. TinyGo writes whole types into a symbol
	// name -- "reflect/types.type:named:internal/reflectlite.Kind",
	// "slices.symMergeCmpFunc[named:internal/fmtsort.KeyValue]" -- and those
	// spellings carry their own slashes and dots. Searching the whole name for
	// the package boundary finds the last slash inside the type instead, which
	// is how a few hundred functions turned into a few hundred packages.
	typed := false
	if i := strings.IndexAny(s, typePunct); i >= 0 {
		s, typed = s[:i], true
	}

	slash := strings.LastIndex(s, "/")
	dot := strings.Index(s[slash+1:], ".")
	if dot < 0 {
		// A name that spelled a type belongs to no package, whether or not it is
		// also compiler-generated: TinyGo's interface wrappers are both, as in
		// "interface:{Error:func:{}{basic:string}}.Error$invoke", and what is
		// left of one after the type is cut off ("interface") names nothing.
		if typed {
			return typePackage
		}
		// No qualifier at all. A generated symbol is still package-named.
		if generated && s != "" {
			return s
		}
		return cPackage
	}
	pkg, rest := s[:slash+1+dot], s[slash+1+dot+1:]
	// GCC gives file-local C symbols a numeric discriminator ("object.0",
	// "crlf_str.1"). That dot separates a suffix, not a package.
	if !generated && !typed && isAllDigits(rest) {
		return cPackage
	}
	if pkg == "" {
		return cPackage
	}
	return pkg
}

// bucketOf reports the package of one of bindiff's own synthetic names, which
// are bracketed so no real symbol can collide with them: [unattributed], and
// the placeholders a WebAssembly module's unnamed items get, "[func 12]" and
// "[data 7]". A placeholder's bucket is its kind, so that thousands of unnamed
// items roll up into one row -- "[func]", "[data]" -- rather than each passing
// for a package, or for a spelled-out type because of the bracket.
func bucketOf(sym string) (string, bool) {
	if !strings.HasPrefix(sym, "[") {
		return "", false
	}
	if kind, _, ok := strings.Cut(sym, " "); ok {
		return kind + "]", true
	}
	return sym, true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
