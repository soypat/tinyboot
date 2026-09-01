package main

import (
	"errors"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Kind is the granularity at which an [Entry] attributes bytes. Kinds form a
// rough hierarchy: a segment contains sections, a section contains symbols, and
// symbols roll up into packages or (with DWARF) source files and lines.
type Kind uint8

const (
	KindSegment Kind = iota // segment
	KindSection             // section
	KindSymbol              // symbol
	KindPackage             // package
	KindFile                // file
	KindLine                // line
)

var kindNames = [...]string{
	KindSegment: "segment",
	KindSection: "section",
	KindSymbol:  "symbol",
	KindPackage: "package",
	KindFile:    "file",
	KindLine:    "line",
}

func (k Kind) String() string {
	if int(k) >= len(kindNames) {
		return "Kind(" + strconv.Itoa(int(k)) + ")"
	}
	return kindNames[k]
}

// ParseKind maps a -kind flag value to its Kind.
func ParseKind(s string) (Kind, error) {
	for i, name := range kindNames {
		if name == s {
			return Kind(i), nil
		}
	}
	return 0, errors.New("unknown kind " + strconv.Quote(s) + ", want one of: " + strings.Join(kindNames[:], ", "))
}

func (k Kind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Kind) UnmarshalText(b []byte) error {
	got, err := ParseKind(string(b))
	if err != nil {
		return err
	}
	*k = got
	return nil
}

// Pos locates an entry in the binary and, where known, in source. Source fields
// are populated only by the DWARF-backed kinds.
type Pos struct {
	Addr uint64 `json:"addr,omitempty"` // Virtual address, 0 when not applicable.
	File string `json:"file,omitempty"` // Source path.
	Line uint32 `json:"line,omitempty"` // Source line.
}

// Unattributed is the name given to the bytes of a section that no entry of the
// requested kind accounts for. Symbol coverage of .text runs 92-97% on the
// repo's fixtures, so without an explicit remainder the columns of a report
// would not sum to the section size.
const Unattributed = "[unattributed]"

// Entry is one row of a profile or a diff, at any granularity.
//
// A profile carries sizes in New and leaves Old zero; [Diff] rebases a pair of
// profiles so that Old holds the first binary's size and New the second's.
type Entry struct {
	Kind    Kind   `json:"kind"`
	Name    string `json:"name"`
	Section string `json:"section,omitempty"` // Owning section, for kinds below section level.
	Pos     Pos    `json:"pos,omitzero"`
	Old     int64  `json:"old"`
	New     int64  `json:"new"`
}

func (e Entry) Delta() int64  { return e.New - e.Old }
func (e Entry) Added() bool   { return e.Old == 0 && e.New != 0 }
func (e Entry) Removed() bool { return e.New == 0 && e.Old != 0 }

// ident is the identity under which two entries from different binaries are
// considered the same item. Address is deliberately excluded: code moves
// between builds without changing size.
func (e Entry) ident() string {
	var b strings.Builder
	b.WriteString(e.Kind.String())
	b.WriteByte('\x00')
	b.WriteString(e.Section)
	b.WriteByte('\x00')
	b.WriteString(e.Name)
	if e.Kind == KindLine {
		b.WriteByte('\x00')
		b.WriteString(e.Pos.File)
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(e.Pos.Line), 10))
	}
	return b.String()
}

// Diff joins two profiles by identity and returns one entry per distinct item.
// Entries present in only one side surface as additions or removals.
func Diff(a, b []Entry) []Entry {
	out := make([]Entry, 0, len(a)+len(b))
	index := make(map[string]int, len(a))
	for _, e := range a {
		id := e.ident()
		if i, ok := index[id]; ok {
			out[i].Old += e.New
			continue
		}
		index[id] = len(out)
		e.Old, e.New = e.New, 0
		out = append(out, e)
	}
	for _, e := range b {
		id := e.ident()
		if i, ok := index[id]; ok {
			out[i].New += e.New
			// Prefer the newer build's position; the old one is stale.
			if e.Pos != (Pos{}) {
				out[i].Pos = e.Pos
			}
			continue
		}
		index[id] = len(out)
		e.Old = 0
		out = append(out, e)
	}
	return out
}

// Total sums a slice into a single entry, for the summary row and the CI gate.
func Total(es []Entry) (old, new int64) {
	for _, e := range es {
		old += e.Old
		new += e.New
	}
	return old, new
}

// SortBySize orders entries by the magnitude of their change, largest first, so
// the rows that explain a size regression come first. Name breaks ties to keep
// output deterministic across runs.
func SortBySize(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		di, dj := es[i].Delta(), es[j].Delta()
		if di < 0 {
			di = -di
		}
		if dj < 0 {
			dj = -dj
		}
		if di != dj {
			return di > dj
		}
		// No change anywhere (a profile, or an identical pair): fall back to size.
		if es[i].New != es[j].New {
			return es[i].New > es[j].New
		}
		if es[i].Section != es[j].Section {
			return es[i].Section < es[j].Section
		}
		return es[i].Name < es[j].Name
	})
}

// Filter keeps entries whose name matches a shell pattern. An empty pattern
// keeps everything.
func Filter(es []Entry, pattern string) ([]Entry, error) {
	if pattern == "" {
		return es, nil
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	out := es[:0:0]
	for _, e := range es {
		ok, _ := path.Match(pattern, e.Name)
		if ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// DropUnchanged removes entries whose size did not move. Only meaningful for a
// diff; a profile has no old side and would be emptied entirely.
func DropUnchanged(es []Entry) []Entry {
	out := es[:0:0]
	for _, e := range es {
		if e.Delta() != 0 {
			out = append(out, e)
		}
	}
	return out
}
