package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/soypat/tinyboot/build/xelf"
)

// placement is one symbol's claim on a range of a section, after overlapping
// claims have been resolved.
type placement struct {
	name    string
	section string
	addr    uint64 // Clamped start address.
	size    int64  // Clamped size; zero for a symbol wholly covered by another.
}

// tiling is the result of dividing a binary's sections among its symbols.
type tiling struct {
	placements []placement
	// remainder holds, per section, the bytes no symbol accounted for.
	remainder map[string]int64
	// order preserves section order for deterministic output.
	order []string
}

// profileSymbols attributes bytes to individual functions and data objects.
//
// Symbols do not tile their section perfectly: on the repo's fixtures .text is
// 92-97% covered, the rest being alignment padding, compiler-emitted stubs and
// symbols whose st_size is zero. The shortfall per section is reported as
// [unattributed] so the rows still sum to the section size.
func profileSymbols(f *xelf.File, mem bool) ([]Entry, error) {
	t, err := tileSymbols(f, mem)
	if err != nil {
		return nil, err
	}
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
	return entries, nil
}

// tileSymbols divides each section's bytes among the symbols that land in it.
func tileSymbols(f *xelf.File, mem bool) (tiling, error) {
	var t tiling
	syms, err := f.AppendTableSymbols(nil)
	if err != nil {
		return t, err
	}
	nsect := f.NumSections()

	// Resolve section names once; symbols reference sections by index.
	secNames := make([]string, nsect)
	secSizes := make([]int64, nsect)
	var nameBuf []byte
	for i := 0; i < nsect; i++ {
		s, err := f.Section(i)
		if err != nil {
			return t, err
		}
		sh := s.SectionHeader()
		nameBuf, err = s.AppendName(nameBuf[:0])
		if err != nil {
			return t, err
		}
		secNames[i] = string(nameBuf)
		switch {
		case mem && sh.Flags&secFlagAlloc == 0:
			secSizes[i] = -1 // Not resident; excluded from a memory profile.
		case !mem && sh.Type == xelf.SecTypeNobits:
			secSizes[i] = 0 // Occupies no file bytes.
		default:
			secSizes[i] = int64(sh.SizeOnFile)
		}
	}

	// Bucket symbols by section so each section can be tiled independently.
	type placed struct {
		name        string
		start, size uint64
	}
	bySection := make(map[int][]placed)
	var strBuf []byte
	for _, sym := range syms {
		typ := xelf.SymType(sym.Info & 0xf)
		if typ != xelf.SymTypeFunc && typ != xelf.SymTypeObject {
			continue
		}
		idx := int(sym.Shndx)
		// SHN_ABS, SHN_COMMON and friends do not name a real section.
		if idx <= 0 || idx >= nsect || xelf.SectionIndex(sym.Shndx) >= xelf.SecIdxReserveLo {
			continue
		}
		if secSizes[idx] <= 0 {
			continue
		}
		strBuf, err = f.AppendSymStr(strBuf[:0], sym.Name)
		if err != nil {
			return t, fmt.Errorf("resolving symbol name: %w", err)
		}
		if len(strBuf) == 0 {
			continue
		}
		bySection[idx] = append(bySection[idx], placed{
			name:  string(strBuf),
			start: sym.Value,
			size:  sym.Size,
		})
	}

	t.placements = make([]placement, 0, len(syms))
	t.remainder = make(map[string]int64, nsect)
	t.order = make([]string, 0, nsect)
	for idx := 0; idx < nsect; idx++ {
		placedSyms := bySection[idx]
		if len(placedSyms) == 0 {
			if secSizes[idx] > 0 {
				t.order = append(t.order, secNames[idx])
				t.remainder[secNames[idx]] = secSizes[idx]
			}
			continue
		}
		t.order = append(t.order, secNames[idx])
		// Tile the section in address order, clamping each symbol so that
		// overlapping symbols -- weak aliases and ifunc pairs share an address
		// -- are counted once. Without this, a section's symbols can sum past
		// its own size and drive the remainder negative.
		sort.Slice(placedSyms, func(i, j int) bool {
			if placedSyms[i].start != placedSyms[j].start {
				return placedSyms[i].start < placedSyms[j].start
			}
			return placedSyms[i].size > placedSyms[j].size
		})
		var cursor uint64
		var attributed int64
		for i, p := range placedSyms {
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
				section: secNames[idx],
				addr:    start,
				size:    size,
			})
		}
		t.remainder[secNames[idx]] = secSizes[idx] - attributed
	}
	return t, nil
}

// profilePackages rolls a symbol profile up by the package each symbol belongs
// to. TinyGo emits fully package-qualified symbol names, so this needs no debug
// information; C symbols have no package and collect under [c].
func profilePackages(f *xelf.File, mem bool) ([]Entry, error) {
	syms, err := profileSymbols(f, mem)
	if err != nil {
		return nil, err
	}
	order := make([]string, 0, 32)
	byPkg := make(map[string]*Entry, 32)
	for _, e := range syms {
		name := packageOf(e.Name)
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
	return entries, nil
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
	if sym == Unattributed {
		return Unattributed
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
