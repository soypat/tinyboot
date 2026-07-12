package filesystem_test

import (
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/soypat/tinyboot/filesystem"
	"github.com/soypat/tinyboot/filesystem/fsfuzz"
)

// The fuzz targets. There is one per backend because go test -fuzz runs one
// target at a time and testing.F has no subtests, so a backend cannot be a
// subtest the way it is everywhere else in this package. They share an encoding,
// which means a corpus file found by one is a valid input to every other:
// copying a find from testdata/fuzz/FuzzLittle into testdata/fuzz/FuzzFAT32 is a
// legitimate and productive thing to do.
//
// No target calls rand. No target may ever call rand. See the fsfuzz package
// documentation for what that buys and what breaking it would cost.

// FuzzFAT32 is the one to run if you are only going to run one. FAT32 is what an
// SD card, a USB stick and a boot partition are formatted as, so it is the code
// that will actually be executed in the field.
func FuzzFAT32(f *testing.F) {
	fuzzBackend(f, fsfuzz.GetFAT32)
}

func FuzzExFAT(f *testing.F) {
	fuzzBackend(f, fsfuzz.GetExFAT)
}

func FuzzLittle(f *testing.F) {
	fuzzBackend(f, fsfuzz.GetLittle)
}

// fuzzBackend is the whole target. Note what it does NOT do: it does not
// allocate a device, or format one, or build a model. Go's fuzzer runs GOMAXPROCS
// workers flat out, so anything allocated here is allocated hundreds of thousands
// of times a second, and a 2 MiB device allocated per iteration will take the
// machine down long before it takes the filesystem down. Everything comes from
// the free list in fsfuzz and goes straight back; see the memory budget there.
func fuzzBackend(f *testing.F, get func() *fsfuzz.Harness) {
	for _, seed := range seedCorpus() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h := get()
		defer h.Release()
		if err := h.Run(fsfuzz.Decode(b)); err != nil {
			t.Fatal(err)
		}
		if n := h.Leaked(); n != 0 {
			t.Fatalf("%d handles were left open, so the pool has lost them", n)
		}
	})
}

// seedCorpus is the starting energy handed to both targets. It is two things
// glued together: the scenarios this package's own unit tests already found
// worth writing, and a batch of random programs from fixed seeds.
//
// The hand-written half matters more than its size suggests. Coverage-guided
// fuzzing is a hill climb, and the flag-conversion code in (*FATFS).mode is at
// the top of a hill a random walk reaches slowly — O_CREATE without O_TRUNC,
// O_TRUNC without O_CREATE and O_APPEND without O_CREATE are each one specific
// bit pattern out of 256. Handing them over for free skips the climb.
func seedCorpus() [][]byte {
	var seeds [][]byte
	for _, prog := range seedPrograms() {
		seeds = append(seeds, prog.Encode())
	}
	rng := rand.New(rand.NewSource(1))
	for range 32 {
		seeds = append(seeds, fsfuzz.GenBytes(rng, 24))
	}
	return seeds
}

// seedPrograms encodes the cases in generic_test.go as programs. Path index 1 is
// "/a" and index 4 is "/d"; see fsfuzz.Paths.
func seedPrograms() []fsfuzz.Program {
	const (
		pathA = 1 // "/a"
		pathD = 4 // "/d"

		wronly = 1
		rdwr   = 2
		create = 1 << 2
		excl   = 1 << 3
		trunc  = 1 << 4
		append = 1 << 5
	)
	write := func(slot uint8, n uint16) fsfuzz.Op {
		return fsfuzz.Op{Code: fsfuzz.OpWrite, Slot: slot, Arg: n}
	}
	open := func(slot, p, flags uint8) fsfuzz.Op {
		return fsfuzz.Op{Code: fsfuzz.OpOpenFile, Slot: slot, PathA: p, Flags: flags}
	}
	closef := func(slot uint8) fsfuzz.Op {
		return fsfuzz.Op{Code: fsfuzz.OpCloseFile, Slot: slot}
	}

	return []fsfuzz.Program{
		// O_CREATE|O_EXCL must fail on the second open. TestOpenCreateExcl.
		{
			open(0, pathA, rdwr|create|excl), closef(0),
			open(0, pathA, rdwr|create|excl),
		},
		// Plain O_CREATE must not truncate an existing file — the case that
		// motivated exporting fat.ModeOpenAlways. TestOpenCreatePreservesContents.
		{
			open(0, pathA, wronly|create|trunc), write(0, 32), closef(0),
			open(0, pathA, wronly|create), closef(0),
			open(0, pathA, 0), {Code: fsfuzz.OpRead, Slot: 0, Arg: 64},
		},
		// O_TRUNC without O_CREATE: empties an existing file, fails on a missing
		// one. TestOpenTruncWithoutCreate.
		{
			open(0, pathA, wronly|create), write(0, 32), closef(0),
			open(0, pathA, wronly|trunc), closef(0),
			{Code: fsfuzz.OpStat, PathA: pathA},
			open(1, pathD, wronly|trunc),
		},
		// O_APPEND must not create, and must extend rather than overwrite.
		// TestOpenAppendDoesNotCreate, TestOpenAppendWrites.
		{
			open(0, pathA, wronly|append),
			open(0, pathA, wronly|create), write(0, 16), closef(0),
			open(0, pathA, wronly|append), write(0, 16), closef(0),
			open(0, pathA, 0), {Code: fsfuzz.OpRead, Slot: 0, Arg: 64},
		},
		// Use after close must report fs.ErrClosed, not reach a recycled handle.
		// TestUseAfterCloseIsSafe.
		{
			open(0, pathA, rdwr|create), closef(0),
			{Code: fsfuzz.OpRead, Slot: 0, Arg: 8},
			write(0, 8),
			{Code: fsfuzz.OpSeek, Slot: 0},
			{Code: fsfuzz.OpTruncate, Slot: 0},
			{Code: fsfuzz.OpSync, Slot: 0},
			closef(0),
		},
		// A directory listing must agree with what was created in it.
		{
			{Code: fsfuzz.OpMkdir, PathA: pathD},
			open(0, 6, wronly|create), closef(0), // "/d/a"
			open(1, 7, wronly|create), closef(1), // "/d/b"
			{Code: fsfuzz.OpOpenDir, PathA: pathD},
			{Code: fsfuzz.OpForEachFile},
			{Code: fsfuzz.OpRewind},
			{Code: fsfuzz.OpReadNext},
			{Code: fsfuzz.OpCloseDir},
		},
	}
}

// TestRandomPrograms is how this package gets the reach of randomized testing
// without the flakiness of a stochastic test. The seeds are fixed and checked
// in, so the programs are the same on every machine and every run: a failure
// here is reproducible by definition, and a change to the generator changes the
// programs but cannot make yesterday's pass become today's mysterious failure.
//
// It is also the fastest way to know the fuzz plumbing still works, since it
// runs under plain go test with no -fuzz flag and no corpus.
func TestRandomPrograms(t *testing.T) {
	// A harness iteration costs tens of microseconds, so this can afford to be
	// large. It should be: a random walk finds the shallow bugs quickly and the
	// specific ones never, which is exactly why TestSeedPrograms exists alongside
	// it.
	const programs = 512
	for _, backend := range eachBackendHarness() {
		t.Run(backend.name, func(t *testing.T) {
			for seed := range int64(programs) {
				rng := rand.New(rand.NewSource(seed))
				runProgram(t, backend, fsfuzz.GenProgram(rng, 64), "seed %d", seed)
			}
		})
	}
}

// TestSeedPrograms runs the hand-written scenarios from seedPrograms against
// both backends, under plain go test.
//
// This is not redundant with TestRandomPrograms, and leaving it out was a real
// hole: a planted bug in (*FATFS).mode — plain O_CREATE truncating an existing
// file, the exact regression TestOpenCreatePreservesContents was written for —
// survived five hundred random programs untouched. The sequence that catches it
// is write, close, reopen with O_CREATE and no O_TRUNC, read back, and a random
// walk essentially never draws four specific operations on one path in order.
//
// Fuzzing is a hill climb. These programs are the trailhead.
func TestSeedPrograms(t *testing.T) {
	for _, backend := range eachBackendHarness() {
		t.Run(backend.name, func(t *testing.T) {
			for i, prog := range seedPrograms() {
				runProgram(t, backend, prog, "seed program %d", i)
			}
		})
	}
}

// runProgram runs one program on a fresh harness and fails t on a disagreement
// or a leaked handle.
func runProgram(t *testing.T, backend backendHarness, prog fsfuzz.Program, what string, args ...any) {
	t.Helper()
	h := backend.get()
	err := h.Run(prog)
	leaked := h.Leaked()
	h.Release()

	if err != nil {
		t.Fatalf("%s: %v", fmt.Sprintf(what, args...), err)
	}
	if leaked != 0 {
		t.Fatalf("%s: %d handles left open", fmt.Sprintf(what, args...), leaked)
	}
}

type backendHarness struct {
	name string
	get  func() *fsfuzz.Harness
}

func eachBackendHarness() []backendHarness {
	return []backendHarness{
		{"fat32", fsfuzz.GetFAT32},
		{"exfat", fsfuzz.GetExFAT},
		{"lfs", fsfuzz.GetLittle},
	}
}

// TestHarnessLeaksNoHandles is the memory discipline made checkable.
//
// A [filesystem.File] returns to its pool in Close and nowhere else, so a fuzz
// program that opens a handle and never closes it costs the pool that handle
// permanently: the next open has to allocate a backend handle again, forever, at
// fuzzing rates. fsfuzz closes what a program leaves open, and this asserts that
// it really does — including for programs that end mid-operation, which is most
// of them.
func TestHarnessLeaksNoHandles(t *testing.T) {
	for _, backend := range eachBackendHarness() {
		t.Run(backend.name, func(t *testing.T) {
			// A program made of nothing but opens: every slot is left open, so
			// closeAll has the most to do.
			var opens fsfuzz.Program
			for slot := range uint8(fsfuzz.NumFiles) {
				opens = append(opens, fsfuzz.Op{
					Code: fsfuzz.OpOpenFile, Slot: slot, PathA: 1 + slot, Flags: 2 | 1<<2,
				})
			}
			for slot := range uint8(fsfuzz.NumDirs) {
				opens = append(opens, fsfuzz.Op{Code: fsfuzz.OpOpenDir, Slot: slot})
			}
			h := backend.get()
			defer h.Release()
			if err := h.Run(opens); err != nil {
				t.Fatal(err)
			}
			if n := h.Leaked(); n != 0 {
				t.Errorf("a program that opens %d handles and closes none leaked %d of them",
					len(opens), n)
			}
		})
	}
}

// TestHarnessReusesDevices checks the free list actually recycles, because the
// cost of it silently not doing so is a 2 MiB allocation per fuzz iteration —
// which does not fail any test, it just kills the machine running the fuzzer.
// This is the guard on that.
func TestHarnessReusesDevices(t *testing.T) {
	for _, backend := range eachBackendHarness() {
		t.Run(backend.name, func(t *testing.T) {
			first := backend.get()
			first.Release()
			second := backend.get()
			defer second.Release()
			if first != second {
				t.Error("a released harness was not handed back out; the free list is not " +
					"recycling and every fuzz iteration will allocate a fresh device")
			}
		})
	}
}

// BenchmarkFuzzIteration measures exactly what a fuzz worker does per iteration.
// It is here to keep B/op small: this number, times GOMAXPROCS, times the exec
// rate, is the memory pressure a fuzzing run puts on the machine, and it is the
// number that has to stay flat.
func BenchmarkFuzzIteration(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	prog := fsfuzz.GenProgram(rng, 64)
	for _, backend := range eachBackendHarness() {
		b.Run(backend.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				h := backend.get()
				if err := h.Run(prog); err != nil {
					b.Fatal(err)
				}
				h.Release()
			}
		})
	}
}

// TestCorpusStable is the enforcement mechanism for the corpus stability
// contract in the fsfuzz package documentation. Without it that contract is a
// comment, and a comment does not stop anyone from inserting an opcode in the
// middle of opTable and silently redefining every corpus file in the repository.
//
// The golden table below pins raw input bytes to the program they decode to. A
// change that renumbers opTable, resizes a record, or repurposes a byte will
// break it loudly and specifically. A change that appends a new operation to a
// reserved slot will not — which is exactly the difference the contract is
// there to draw.
//
// If this test fails and the change was intentional, the corpus in
// testdata/fuzz is no longer describing what it used to. Regenerate it; do not
// just update the golden.
func TestCorpusStable(t *testing.T) {
	for _, test := range []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "empty input decodes to the empty program",
			in:   nil,
			want: "",
		},
		{
			name: "a lone version byte decodes to the empty program",
			in:   []byte{fsfuzz.Version},
			want: "",
		},
		{
			name: "a partial trailing record is zero-padded, not dropped",
			in:   []byte{fsfuzz.Version, 0x00, 0x01},
			want: `  0: open      f1 "/" O_RDONLY` + "\n",
		},
		{
			name: "opcode dispatch, path alphabet and flag packing",
			in: []byte{
				fsfuzz.Version,
				0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, // open f0 "/a" O_RDWR|O_CREATE
				0x0f, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, // write f0 n=32
				0x18, 0x00, 0x00, 0x00, 0x00, 0xfb, 0xff, 0x02, // seek f0 off=-5 SEEK_END
				0x09, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, // read f0 n=16
				0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // close f0
			},
			want: `  0: open      f0 "/a" O_RDWR|O_CREATE
  1: write     f0 n=32
  2: seek      f0 off=-5 whence=SEEK_END
  3: read      f0 n=16
  4: close     f0
`,
		},
		{
			name: "reserved opcode slots decode to nop, so a new op cannot shift an old one",
			in: []byte{
				fsfuzz.Version,
				0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // slot 48: reserved
				0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // slot 63: reserved
				0x1f, 0x02, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, // stat "/nnn..." (the too-long name)
			},
			want: "  0: nop\n  1: nop\n  2: stat      \"/" + longName() + "\"\n",
		},
		{
			name: "the invalid access mode O_WRONLY|O_RDWR survives decoding, so it can be rejected",
			in:   []byte{fsfuzz.Version, 0x00, 0x00, 0x02, 0x00, 0x43, 0x00, 0x00, 0x00},
			want: `  0: open      f0 "/b" O_WRONLY|O_RDWR(invalid)|O_SYNC` + "\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := fsfuzz.Decode(test.in).String()
			if got != test.want {
				t.Errorf("decode is not what it was when the corpus was recorded.\ngot:\n%s\nwant:\n%s", got, test.want)
			}
		})
	}
}

func longName() string {
	name := make([]byte, 300)
	for i := range name {
		name[i] = 'n'
	}
	return string(name)
}

// TestEncodeRoundTrips checks Decode(Encode(p)) == p, which is what makes the
// hand-written seed programs above a valid corpus and what lets a find be edited
// by hand and fed back in.
func TestEncodeRoundTrips(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for range 200 {
		want := fsfuzz.GenProgram(rng, 16)
		got := fsfuzz.Decode(want.Encode())
		if len(got) != len(want) {
			t.Fatalf("round trip changed length: %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("round trip changed op %d:\ngot  %+v\nwant %+v", i, got[i], want[i])
			}
		}
	}
}

// FuzzPaths is the panic hunt, kept separate from the differential fuzzer on
// purpose. It feeds arbitrary strings — empty, trailing slashes, "..", NUL
// bytes, invalid UTF-8 — to every operation that takes a path, and asserts one
// thing: it does not panic. Whether a backend accepts "/d/" or rejects it is not
// something either one defines, so it is not something the model in fsfuzz
// should be forced to take a position on. Keeping those paths out of the model's
// alphabet is what lets the model stay strict about the paths it does handle.
func FuzzPaths(f *testing.F) {
	for _, seed := range []string{
		"", "/", ".", "..", "/..", "/../..", "//", "/d/", "/a//b", "\x00", "/\x00a",
		"/very/deep/path/that/does/not/exist", "\xff\xfe", "/a/../a",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		h := fsfuzz.GetLittle()
		defer h.Release()
		fsys := h.FS()
		// Any error is fine. A panic is not, and neither is a hang.
		fsys.Mkdir(path)
		fsys.Stat(path)
		fsys.Remove(path)
		fsys.Rename(path, "/tmp")
		fsys.Rename("/tmp", path)
		if d, err := fsys.OpenDir(path); err == nil {
			d.ForEachFile(func(filesystem.FileInfo) error { return nil })
			d.Close()
		}
		if fp, err := fsys.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o666); err == nil {
			fp.WriteString("x")
			fp.Close()
		}
	})
}
