package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Report is the top level of the JSON output. It keeps the summary next to the
// rows so a CI job can read a verdict without re-summing the entries.
type Report struct {
	Mode    string  `json:"mode"` // "profile" or "diff"
	Kind    Kind    `json:"kind"`
	Old     string  `json:"old,omitempty"` // Input path, diff mode only.
	New     string  `json:"new"`
	Entries []Entry `json:"entries"`
	Summary Summary `json:"summary"`
}

type Summary struct {
	Old   int64 `json:"old"`
	New   int64 `json:"new"`
	Delta int64 `json:"delta"`
}

func renderJSON(w io.Writer, r Report) error {
	if r.Entries == nil {
		r.Entries = []Entry{} // Render as [] rather than null.
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// signed renders a delta with an explicit sign so growth and shrinkage are
// distinguishable at a glance in a column of numbers.
func signed(v int64) string {
	if v > 0 {
		return "+" + strconv.FormatInt(v, 10)
	}
	return strconv.FormatInt(v, 10)
}

// percent renders the relative change. A new item has no meaningful percentage.
func percent(old, new int64) string {
	if old == 0 {
		if new == 0 {
			return ""
		}
		return "new"
	}
	if new == 0 {
		return "gone"
	}
	return fmt.Sprintf("%+.1f%%", 100*float64(new-old)/float64(old))
}

// displayName is the label shown for an entry. Remainder rows exist once per
// section, so they carry the section name to stay distinguishable.
func displayName(e Entry) string {
	if e.Name == Unattributed && e.Section != "" {
		return e.Name + " " + e.Section
	}
	return e.Name
}

// elide shortens a label to width, trimming the front rather than the back.
// Names here are source paths and package-qualified symbols, whose informative
// part -- the file, the function -- is at the end.
func elide(s string, width int) string {
	if len(s) <= width || width < 2 {
		return s
	}
	return "…" + s[len(s)-(width-1):]
}

func renderText(w io.Writer, r Report) error {
	diff := r.Mode == "diff"

	// Size the name column to its contents so long TinyGo symbol names stay
	// readable, but cap it so one outlier cannot wreck the layout.
	const maxName = 60
	nameWidth := len("NAME")
	for _, e := range r.Entries {
		if n := len(displayName(e)); n > nameWidth {
			nameWidth = n
		}
	}
	if nameWidth > maxName {
		nameWidth = maxName
	}

	if diff {
		fmt.Fprintf(w, "%-8s %-*s %10s %10s %10s %8s\n", "KIND", nameWidth, "NAME", "OLD", "NEW", "DELTA", "")
	} else {
		fmt.Fprintf(w, "%-8s %-*s %10s\n", "KIND", nameWidth, "NAME", "SIZE")
	}
	for _, e := range r.Entries {
		name := elide(displayName(e), nameWidth)
		if diff {
			fmt.Fprintf(w, "%-8s %-*s %10d %10d %10s %8s\n",
				e.Kind, nameWidth, name, e.Old, e.New, signed(e.Delta()), percent(e.Old, e.New))
		} else {
			fmt.Fprintf(w, "%-8s %-*s %10d\n", e.Kind, nameWidth, name, e.New)
		}
	}

	if diff {
		fmt.Fprintf(w, "%-8s %-*s %10d %10d %10s %8s\n",
			"TOTAL", nameWidth, "", r.Summary.Old, r.Summary.New,
			signed(r.Summary.Delta), percent(r.Summary.Old, r.Summary.New))
	} else {
		fmt.Fprintf(w, "%-8s %-*s %10d\n", "TOTAL", nameWidth, "", r.Summary.New)
	}
	return nil
}
