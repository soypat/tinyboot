// Command bindiff characterizes where the bytes of an ELF binary go, and what
// changed between two builds of it.
//
// It reports at several granularities, from whole segments down to source
// lines, and every granularity reconciles: the rows of a report sum to the size
// of what they describe, with an explicit [unattributed] remainder wherever the
// available information does not cover everything.
//
//	bindiff profile firmware.elf
//	bindiff -kind=package profile firmware.elf
//	bindiff -json diff old.elf new.elf
//	bindiff -threshold=1024 diff old.elf new.elf   # exits non-zero on growth
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/soypat/tinyboot/build/xelf"
)

type Flags struct {
	kind      Kind
	json      bool
	mem       bool
	all       bool
	top       int
	filter    string
	threshold int64
}

func main() {
	log.SetFlags(0)
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var flags Flags
	kindName := flag.String("kind", "section", "Granularity: segment, section, symbol, package, file or line.")
	flag.BoolVar(&flags.json, "json", false, "Emit JSON instead of a text table.")
	flag.BoolVar(&flags.mem, "mem", false, "Report memory footprint (includes .bss) instead of file bytes.")
	flag.BoolVar(&flags.all, "all", false, "In diff mode, also show entries whose size did not change.")
	flag.IntVar(&flags.top, "top", 0, "Show only the N largest rows. 0 shows all.")
	flag.StringVar(&flags.filter, "filter", "", "Keep only entries whose name matches this shell pattern.")
	flag.Int64Var(&flags.threshold, "threshold", -1, "CI gate: exit non-zero if total growth exceeds this many bytes. Negative disables.")
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(output, "\tavailable commands: [profile, diff]\n")
		fmt.Fprintf(output, "Example:\n\tbindiff [flags] profile <filename>\n")
		fmt.Fprintf(output, "\tbindiff [flags] diff <old> <new>\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	kind, err := ParseKind(*kindName)
	if err != nil {
		flag.Usage()
		return err
	}
	flags.kind = kind

	command := flag.Arg(0)
	switch command {
	case "profile":
		if flag.NArg() != 2 {
			flag.Usage()
			return errors.New("profile takes exactly one filename")
		}
		return profile(os.Stdout, flag.Arg(1), flags)
	case "diff":
		if flag.NArg() != 3 {
			flag.Usage()
			return errors.New("diff takes exactly two filenames")
		}
		return diff(os.Stdout, flag.Arg(1), flag.Arg(2), flags)
	case "":
		flag.Usage()
		return errors.New("no command given")
	default:
		flag.Usage()
		return errors.New("unknown command: " + command)
	}
}

// profileFile opens path and produces the entries for the requested kind.
func profileFile(path string, flags Flags) ([]Entry, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()
	info, err := fp.Stat()
	if err != nil {
		return nil, err
	}
	return profileReader(fp, info.Size(), flags)
}

func profileReader(r io.ReaderAt, size int64, flags Flags) ([]Entry, error) {
	var f xelf.File
	if err := f.Read(r); err != nil {
		return nil, err
	}
	switch flags.kind {
	case KindSegment:
		return profileSegments(&f, flags.mem)
	case KindSection:
		return profileSections(&f, size, flags.mem)
	case KindSymbol:
		return profileSymbols(&f, flags.mem)
	case KindPackage:
		return profilePackages(&f, flags.mem)
	case KindFile:
		return profileSource(&f, flags.mem, false)
	case KindLine:
		return profileSource(&f, flags.mem, true)
	default:
		return nil, fmt.Errorf("granularity %q is not implemented yet", flags.kind)
	}
}

func profile(w io.Writer, path string, flags Flags) error {
	entries, err := profileFile(path, flags)
	if err != nil {
		return err
	}
	// Summarize before trimming, so the total describes the whole binary rather
	// than whichever rows survived -top and -filter.
	_, total := Total(entries)

	entries, err = present(entries, flags)
	if err != nil {
		return err
	}
	return emit(w, Report{
		Mode:    "profile",
		Kind:    flags.kind,
		New:     path,
		Entries: entries,
		Summary: Summary{New: total},
	}, flags)
}

func diff(w io.Writer, oldPath, newPath string, flags Flags) error {
	oldEntries, err := profileFile(oldPath, flags)
	if err != nil {
		return fmt.Errorf("reading %s: %w", oldPath, err)
	}
	newEntries, err := profileFile(newPath, flags)
	if err != nil {
		return fmt.Errorf("reading %s: %w", newPath, err)
	}
	entries := Diff(oldEntries, newEntries)

	// Summarize before trimming, so the total describes the whole binary rather
	// than whichever rows survived -top and -filter.
	sumOld, sumNew := Total(entries)

	if !flags.all {
		entries = DropUnchanged(entries)
	}
	entries, err = present(entries, flags)
	if err != nil {
		return err
	}
	err = emit(w, Report{
		Mode:    "diff",
		Kind:    flags.kind,
		Old:     oldPath,
		New:     newPath,
		Entries: entries,
		Summary: Summary{Old: sumOld, New: sumNew, Delta: sumNew - sumOld},
	}, flags)
	if err != nil {
		return err
	}
	if growth := sumNew - sumOld; flags.threshold >= 0 && growth > flags.threshold {
		return fmt.Errorf("size grew by %d bytes, over the %d byte threshold", growth, flags.threshold)
	}
	return nil
}

// present applies the display-only transforms: filtering, ordering and trimming.
func present(entries []Entry, flags Flags) ([]Entry, error) {
	entries, err := Filter(entries, flags.filter)
	if err != nil {
		return nil, fmt.Errorf("bad -filter pattern: %w", err)
	}
	SortBySize(entries)
	if flags.top > 0 && len(entries) > flags.top {
		entries = entries[:flags.top]
	}
	return entries, nil
}

func emit(w io.Writer, r Report, flags Flags) error {
	if flags.json {
		return renderJSON(w, r)
	}
	return renderText(w, r)
}
