package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/soypat/tinyboot/build/elfutil"
	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xelf"
)

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
func buildLineIndex(sec xdwarf.Sections, size int64) (*lineIndex, error) {
	idx := &lineIndex{}
	if sec.Line == nil || size == 0 {
		return idx, nil
	}
	// Intern file names: a compilation unit repeats the same handful of paths
	// across thousands of rows.
	interned := make(map[string]string, 64)
	var nameBuf []byte
	// One unit and one scratch buffer serve the whole section. A header too
	// large for aux reports the size it needs, so the buffer grows to the
	// biggest header the binary has and then stops.
	var u xdwarf.LineUnit
	aux := make([]byte, 4096)

	for off := int64(0); off < size; {
		next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
		var small xdwarf.AuxTooSmallError
		if errors.As(err, &small) {
			aux = make([]byte, small.Need)
			continue
		}
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
	var sec xdwarf.Sections
	var readers elfutil.DWARFReaders
	lineSize, err := elfutil.LoadDWARF(&sec, &readers, f)
	if err != nil {
		return nil, err
	}
	idx, err := buildLineIndex(sec, lineSize)
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
