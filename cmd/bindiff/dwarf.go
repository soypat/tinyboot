package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/soypat/archive/zlib"

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
	// maxEnd[i] is the largest end among ranges[:i+1]. Sorting by start leaves
	// the ends in no order at all -- a sequence may emit a long range after a
	// short one, and sequences interleave -- so a search for "the first range
	// that reaches this address" cannot test ends directly. The running maximum
	// can be tested: it never decreases, and once it passes an address every
	// range that could reach it lies at or after that point.
	maxEnd []uint64
}

// buildLineIndex walks every line program in the binary and converts the line
// matrix into address ranges.
//
// The line table records positions at points, not extents: each row holds until
// the next row in the same sequence, and an end_sequence row closes the range
// before it. Ranges from different sequences may interleave in address order,
// so the whole set is sorted once at the end.
func buildLineIndex(sec xdwarf.Sections, size int64, aux []byte) (*lineIndex, error) {
	idx := &lineIndex{}
	if sec.Line == nil || size == 0 {
		return idx, nil
	}
	// Intern file names: a compilation unit repeats the same handful of paths
	// across thousands of rows.
	interned := make(map[string]string, 64)
	var nameBuf []byte
	// One unit serves the whole section, its tables reused rather than rebuilt.
	var u xdwarf.LineUnit

	for off := int64(0); off < size; {
		next, err := xdwarf.DecodeLineUnit(&u, sec, off, size, aux)
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
		for r := range u.Rows {
			flush(r.Address)
			if r.EndSequence {
				break
			}
			nameBuf, err = u.AppendFileName(nameBuf[:0], r.File)
			if err != nil {
				// A row naming a file outside the table is not worth failing
				// the whole binary over; it lands in the remainder instead.
				break
			}
			name := xdwarf.CleanPath(string(nameBuf))
			canonical, ok := interned[name]
			if !ok {
				canonical = name
				interned[name] = canonical
			}
			pending = srcRange{start: r.Address, file: canonical, line: r.Line}
			havePending = true
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
	idx.buildMaxEnd()
	return idx, nil
}

// buildMaxEnd fills the running maximum the overlap search binary-searches on.
// It must run after ranges is in its final order.
func (idx *lineIndex) buildMaxEnd() {
	idx.maxEnd = make([]uint64, len(idx.ranges))
	var m uint64
	for i, r := range idx.ranges {
		if r.end > m {
			m = r.end
		}
		idx.maxEnd[i] = m
	}
}

// defaultAux starts the scratch buffer comfortably past any ordinary line
// program header; the grow-and-retry below covers the rest.
const defaultAux = 4096

// loadLineIndex builds the line index, growing the decoder's buffers and
// loading again until they are large enough.
//
// Retrying means starting over rather than resuming: a compressed .debug_line
// is inflated as it is walked and cannot be rewound, so both a larger aux and a
// zlib reader the binary turned out to need require a fresh load.
func loadLineIndex(f *xelf.File, rr *elfutil.DWARFReaders) (*lineIndex, error) {
	aux := make([]byte, defaultAux)
	for {
		// The lookback the streaming path needs is a function of aux, so the two
		// grow together or the walk fails partway through.
		rr.Stream = resize(rr.Stream, elfutil.StreamBufferFor(len(aux)))
		var sec xdwarf.Sections
		size, err := elfutil.LoadDWARF(&sec, rr, f)
		if errors.Is(err, elfutil.ErrNoZlib) {
			// The gc toolchain compresses DWARF by default, so this is the
			// ordinary path for a binary that was not built with TinyGo. The
			// inflater is only built once the binary proves it needs one.
			zr := new(zlib.Reader)
			if err := zr.Configure(zlib.DefaultConfig()); err != nil {
				return nil, err
			}
			rr.Zlib = zr
			continue
		}
		if err != nil {
			return nil, err
		}
		idx, err := buildLineIndex(sec, size, aux)
		var small xdwarf.AuxTooSmallError
		if errors.As(err, &small) {
			aux = make([]byte, small.Need)
			continue
		}
		return idx, err
	}
}

// resize returns b with length n, reusing its memory when it already has room.
func resize(b []byte, n int) []byte {
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

// visitOverlaps calls fn for each source range overlapping [start, end), with
// the number of bytes of the overlap.
func (idx *lineIndex) visitOverlaps(start, end uint64, fn func(r srcRange, n int64)) {
	if start >= end || len(idx.ranges) == 0 {
		return
	}
	// First range that could reach start. Testing ends directly would be a
	// search over unsorted data: ranges are ordered by start, and a predicate on
	// end flips back and forth, so sort.Search is free to land past a range that
	// does overlap. The running maximum is what makes the search well defined.
	i := sort.Search(len(idx.ranges), func(i int) bool {
		return idx.maxEnd[i] > start
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
	var readers elfutil.DWARFReaders
	idx, err := loadLineIndex(f, &readers)
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
