package filesystem_test

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
	"github.com/soypat/tinyboot/filesystem"
)

// TestPoolRecyclesHandles checks the core claim of FS: a File closed and then
// reopened comes back as the same object, so a program that closes what it opens
// stops allocating handles.
func TestPoolRecyclesHandles(t *testing.T) {
	t.Run("fat", func(t *testing.T) {
		fsys := filesystem.NewFAT(newFATFS(t))
		testPoolRecycles(t, fsys.Create, fsys.Open)
	})
	t.Run("lfs", func(t *testing.T) {
		fsys := filesystem.NewLittle(newLittleFS(t))
		testPoolRecycles(t, fsys.Create, fsys.Open)
	})
}

func testPoolRecycles[F filesystem.FileHandle](
	t *testing.T,
	create func(string) (*filesystem.File[F], error),
	open func(string) (*filesystem.File[F], error),
) {
	t.Helper()
	f1, err := create("/pooled.txt")
	if err != nil {
		t.Fatal("create:", err)
	}
	if err = f1.Close(); err != nil {
		t.Fatal("close:", err)
	}
	f2, err := open("/pooled.txt")
	if err != nil {
		t.Fatal("reopen:", err)
	}
	defer f2.Close()
	if f1 != f2 {
		t.Errorf("reopen after close returned a fresh File %p, want the pooled %p", f2, f1)
	}
}

// TestUseAfterCloseIsSafe checks that a closed File cannot reach its handle. The
// handle is back in the pool and may already belong to another open, so every
// method must refuse rather than corrupt it.
func TestUseAfterCloseIsSafe(t *testing.T) {
	t.Run("fat", func(t *testing.T) {
		fsys := filesystem.NewFAT(newFATFS(t))
		f, err := fsys.Create("/closed.txt")
		if err != nil {
			t.Fatal("create:", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal("close:", err)
		}
		testUseAfterClose(t, f)
	})
	t.Run("lfs", func(t *testing.T) {
		fsys := filesystem.NewLittle(newLittleFS(t))
		f, err := fsys.Create("/closed.txt")
		if err != nil {
			t.Fatal("create:", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal("close:", err)
		}
		testUseAfterClose(t, f)
	})
}

func testUseAfterClose[F filesystem.FileHandle](t *testing.T, f *filesystem.File[F]) {
	t.Helper()
	buf := make([]byte, 4)
	ops := map[string]func() error{
		"Read":        func() error { _, err := f.Read(buf); return err },
		"ReadAt":      func() error { _, err := f.ReadAt(buf, 0); return err },
		"Write":       func() error { _, err := f.Write(buf); return err },
		"WriteAt":     func() error { _, err := f.WriteAt(buf, 0); return err },
		"WriteString": func() error { _, err := f.WriteString("x"); return err },
		"Seek":        func() error { _, err := f.Seek(0, 0); return err },
		"Truncate":    func() error { return f.Truncate(0) },
		"Sync":        func() error { return f.Sync() },
		"Close":       func() error { return f.Close() },
	}
	for name, op := range ops {
		err := op()
		if err == nil {
			t.Errorf("%s on a closed File succeeded, want failure", name)
			continue
		}
		if !errors.Is(err, fs.ErrClosed) {
			t.Errorf("%s on a closed File: error %v does not match fs.ErrClosed", name, err)
		}
	}
}

// TestPoolSteadyStateAllocs checks the payoff: once the pool is warm, an
// open/write/close cycle allocates nothing of its own. A nonzero result here
// means a handle is escaping the pool on every open.
func TestPoolSteadyStateAllocs(t *testing.T) {
	t.Run("fat", func(t *testing.T) {
		fsys := filesystem.NewFAT(newFATFS(t))
		testSteadyStateAllocs(t, func() {
			f, err := fsys.OpenFile("/allocs.txt", os.O_WRONLY|os.O_CREATE, 0o666)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
		})
	})
	t.Run("lfs", func(t *testing.T) {
		fsys := filesystem.NewLittle(newLittleFS(t))
		testSteadyStateAllocs(t, func() {
			f, err := fsys.OpenFile("/allocs.txt", os.O_WRONLY|os.O_CREATE, 0o666)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
		})
	})
}

func testSteadyStateAllocs(t *testing.T, cycle func()) {
	t.Helper()
	cycle() // Warm the pool: the first open necessarily allocates its handle.
	if n := testing.AllocsPerRun(100, cycle); n != 0 {
		t.Errorf("open/close cycle allocates %v objects in steady state, want 0", n)
	}
}

// newFATFS and newLittleFS build a freshly formatted filesystem, mirroring the
// helpers in generic_test.go but returning the FSNoAlloc implementation so it can
// be wrapped in a pooled FS.
func newFATFS(t *testing.T) *filesystem.FATFS {
	t.Helper()
	const sectorSize, sectors = 512, 32000
	bd := newRamBD(sectorSize, sectors)
	var fmtr fat.Formatter
	if err := fmtr.Format(bd, sectorSize, sectors, fat.FormatConfig{Format: fat.FormatExFAT}); err != nil {
		t.Fatal("format fat:", err)
	}
	fsys := new(filesystem.FATFS)
	if err := fsys.Mount(bd, sectorSize, fat.ModeRW); err != nil {
		t.Fatal("mount fat:", err)
	}
	return fsys
}

func newLittleFS(t *testing.T) *filesystem.LittleFS {
	t.Helper()
	const pageSize, blockSize, blocks = 256, 4096, 64
	bd := newRamBD(pageSize, blockSize/pageSize*blocks)
	var fmtr lfs.Formatter
	if err := fmtr.Format(bd, pageSize, blockSize, blocks, lfs.FormatConfig{}); err != nil {
		t.Fatal("format lfs:", err)
	}
	fsys := new(filesystem.LittleFS)
	if err := fsys.Mount(bd, pageSize, blockSize, lfs.ModeRW); err != nil {
		t.Fatal("mount lfs:", err)
	}
	return fsys
}
