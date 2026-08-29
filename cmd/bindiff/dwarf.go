package main

import (
	"fmt"
	"sort"

	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xelf"
)

// loadDWARF extracts the line-number sections from an ELF, applying the
// relocations that target them.
//
// TinyGo emits .rel.debug_* alongside its debug sections, leaving addresses
// unresolved in the file; without relocating, every line table row would report
// address zero. Relocations are matched to their target through sh_info rather
// than being concatenated, since .rela.dyn targets .got and would corrupt a
// debug section it was applied to.
func loadDWARF(f *xelf.File) (xdwarf.Sections, error) {
	hdr := f.Header()
	sec := xdwarf.Sections{ByteOrder: hdr.ByteOrder()}

	// Symbols are only needed if something actually requires relocation.
	var syms []xelf.Sym
	var symsLoaded bool

	var nameBuf []byte
	for i := 0; i < f.NumSections(); i++ {
		s, err := f.Section(i)
		if err != nil {
			return sec, err
		}
		nameBuf, err = s.AppendName(nameBuf[:0])
		if err != nil {
			return sec, err
		}
		var dst *[]byte
		switch string(nameBuf) {
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
			return sec, fmt.Errorf("reading %s: %w", nameBuf, err)
		}
		if rels, ok := f.RelocationsFor(i); ok {
			if !symsLoaded {
				syms, err = f.AppendTableSymbols(nil)
				if err != nil {
					return sec, fmt.Errorf("symbol table needed for relocation: %w", err)
				}
				symsLoaded = true
			}
			relData, err := rels.AppendData(nil)
			if err != nil {
				return sec, err
			}
			// Relocation types this build does not implement leave those
			// particular addresses unresolved; the rest of the section is still
			// usable, and unresolved rows simply fail to match a symbol.
			_ = xelf.ApplyRelocations(data, relData, syms, hdr)
		}
		*dst = data
	}
	return sec, nil
}

// srcRange is a half-open address range attributed to one source position.
type srcRange struct {
	start, end uint64
	file       string
	line       uint32
}

// lineIndex answers "which source position does this address belong to".
type lineIndex struct {
	ranges []srcRange // Sorted by start, non-overlapping within a sequence.
}

// buildLineIndex walks every line program in the binary and converts the line
// matrix into address ranges.
//
// The line table records positions at points, not extents: each row holds until
// the next row in the same sequence, and an end_sequence row closes the range
// before it. Ranges from different sequences may interleave in address order,
// so the whole set is sorted once at the end.
func buildLineIndex(sec xdwarf.Sections) (*lineIndex, error) {
	idx := &lineIndex{}
	if len(sec.Line) == 0 {
		return idx, nil
	}
	// Intern file names: a compilation unit repeats the same handful of paths
	// across thousands of rows.
	interned := make(map[string]string, 64)
	var nameBuf []byte

	for off := 0; off < len(sec.Line); {
		u, next, err := sec.NextLineUnit(off)
		if err != nil {
			return nil, fmt.Errorf("line unit at %d: %w", off, err)
		}
		if next <= off {
			return nil, fmt.Errorf("line unit at %d did not advance", off)
		}

		// pending is the row awaiting an end address from its successor.
		var pending srcRange
		var havePending bool
		flush := func(end uint64) {
			if havePending && end > pending.start {
				pending.end = end
				idx.ranges = append(idx.ranges, pending)
			}
			havePending = false
		}
		err = u.VisitRows(func(r xdwarf.Row) error {
			flush(r.Address)
			if r.EndSequence {
				return nil
			}
			nameBuf, err = u.AppendFileName(nameBuf[:0], r.File)
			if err != nil {
				// A row naming a file outside the table is not worth failing
				// the whole binary over; it lands in the remainder instead.
				return nil
			}
			name := xdwarf.CleanPath(string(nameBuf))
			canonical, ok := interned[name]
			if !ok {
				canonical = name
				interned[name] = canonical
			}
			pending = srcRange{start: r.Address, file: canonical, line: r.Line}
			havePending = true
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("line unit at %d: %w", off, err)
		}
		flush(0) // A sequence that never ended contributes nothing.
		off = next
	}
	sort.Slice(idx.ranges, func(i, j int) bool {
		if idx.ranges[i].start != idx.ranges[j].start {
			return idx.ranges[i].start < idx.ranges[j].start
		}
		return idx.ranges[i].end < idx.ranges[j].end
	})
	return idx, nil
}

// visitOverlaps calls fn for each source range overlapping [start, end), with
// the number of bytes of the overlap.
func (idx *lineIndex) visitOverlaps(start, end uint64, fn func(r srcRange, n int64)) {
	if start >= end || len(idx.ranges) == 0 {
		return
	}
	// First range that could overlap: the last one starting at or before start.
	i := sort.Search(len(idx.ranges), func(i int) bool {
		return idx.ranges[i].end > start
	})
	for ; i < len(idx.ranges) && idx.ranges[i].start < end; i++ {
		r := idx.ranges[i]
		lo, hi := r.start, r.end
		if lo < start {
			lo = start
		}
		if hi > end {
			hi = end
		}
		if hi > lo {
			fn(r, int64(hi-lo))
		}
	}
}

// profileSource attributes bytes to source files, or to individual source lines
// when byLine is set.
//
// Attribution runs through symbols rather than over raw addresses, so that the
// result still reconciles against sections: a symbol's bytes are split among
// the source ranges covering it, and whatever the line table does not cover --
// data, padding, assembly with no line info -- stays in [unattributed].
func profileSource(f *xelf.File, mem, byLine bool) ([]Entry, error) {
	t, err := tileSymbols(f, mem)
	if err != nil {
		return nil, err
	}
	sec, err := loadDWARF(f)
	if err != nil {
		return nil, err
	}
	if len(sec.Line) == 0 {
		return nil, fmt.Errorf("binary has no .debug_line section; source attribution needs debug info")
	}
	idx, err := buildLineIndex(sec)
	if err != nil {
		return nil, err
	}

	kind := KindFile
	if byLine {
		kind = KindLine
	}

	type key struct {
		file string
		line uint32
	}
	agg := make(map[key]*Entry, 256)
	order := make([]key, 0, 256)
	// Bytes a symbol covered that the line table said nothing about, kept per
	// section so the remainder stays attributable to where it came from.
	unmapped := make(map[string]int64, len(t.order))

	for _, p := range t.placements {
		if p.size == 0 {
			continue
		}
		var covered int64
		idx.visitOverlaps(p.addr, p.addr+uint64(p.size), func(r srcRange, n int64) {
			k := key{file: r.file}
			if byLine {
				k.line = r.line
			}
			e, ok := agg[k]
			if !ok {
				order = append(order, k)
				agg[k] = &Entry{
					Kind: kind,
					Name: sourceName(k.file, k.line, byLine),
					Pos:  Pos{File: k.file, Line: k.line},
				}
				e = agg[k]
			}
			e.New += n
			covered += n
		})
		if rem := p.size - covered; rem > 0 {
			unmapped[p.section] += rem
		}
	}

	entries := make([]Entry, 0, len(order)+len(t.order))
	for _, k := range order {
		entries = append(entries, *agg[k])
	}
	// Fold the symbol-level remainder together with the bytes symbols claimed
	// but the line table could not place, so the total still matches a section
	// profile exactly.
	for _, section := range t.order {
		total := t.remainder[section] + unmapped[section]
		if total != 0 {
			entries = append(entries, Entry{
				Kind: kind, Name: Unattributed, Section: section, New: total,
			})
		}
	}
	return entries, nil
}

func sourceName(file string, line uint32, byLine bool) string {
	if !byLine {
		return file
	}
	return fmt.Sprintf("%s:%d", file, line)
}
