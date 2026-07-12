package filesystem_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
	"github.com/soypat/tinyboot/filesystem"
	"github.com/soypat/tinyboot/filesystem/fsfuzz"
)

// backend is the portable surface the cross-backend tests exercise. It exists so
// a single table of cases runs identically against FAT and littlefs; the two
// implementations below are the only backend-specific code in this file.
type backend interface {
	open(path string, flag int) (filesystem.FileHandle, error)
	stat(path string) (filesystem.FileInfo, error)
	mkdir(path string) error
}

type fatBackend struct{ fsys *filesystem.FATFS }

func (b fatBackend) open(path string, flag int) (filesystem.FileHandle, error) {
	f := new(fat.File)
	err := b.fsys.OpenFile(f, path, flag, 0o666)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (b fatBackend) stat(path string) (filesystem.FileInfo, error) {
	info := new(fat.FileInfo)
	err := b.fsys.Stat(path, info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (b fatBackend) mkdir(path string) error { return b.fsys.Mkdir(path) }

type lfsBackend struct{ fsys *filesystem.LittleFS }

func (b lfsBackend) open(path string, flag int) (filesystem.FileHandle, error) {
	f := new(lfs.File)
	err := b.fsys.OpenFile(f, path, flag, 0o666)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (b lfsBackend) stat(path string) (filesystem.FileInfo, error) {
	info := new(lfs.FileInfo)
	err := b.fsys.Stat(path, info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (b lfsBackend) mkdir(path string) error { return b.fsys.Mkdir(path) }

func newFATBackend(t *testing.T) backend {
	t.Helper()
	const sectorSize, sectors = 512, 32000
	bd := fsfuzz.NewRAM(sectorSize, sectors)
	var fmtr fat.Formatter
	// exFAT, because fat's FAT12/16/32 mkfs is not implemented yet
	// (fat/format.go formatFAT). The flag conversion under test is shared by
	// every FAT variant, so this exercises the same code path.
	if err := fmtr.Format(bd, sectorSize, sectors, fat.FormatConfig{Format: fat.FormatExFAT}); err != nil {
		t.Fatal("format fat:", err)
	}
	var fsys filesystem.FATFS
	if err := fsys.Mount(bd, sectorSize, fat.ModeRW); err != nil {
		t.Fatal("mount fat:", err)
	}
	return fatBackend{fsys: &fsys}
}

func newLFSBackend(t *testing.T) backend {
	t.Helper()
	const pageSize, blockSize, blocks = 256, 4096, 64
	bd := fsfuzz.NewRAM(pageSize, blockSize/pageSize*blocks)
	var fmtr lfs.Formatter
	if err := fmtr.Format(bd, pageSize, blockSize, blocks, lfs.FormatConfig{}); err != nil {
		t.Fatal("format lfs:", err)
	}
	var fsys filesystem.LittleFS
	if err := fsys.Mount(bd, pageSize, blockSize, lfs.ModeRW); err != nil {
		t.Fatal("mount lfs:", err)
	}
	return lfsBackend{fsys: &fsys}
}

// eachBackend runs fn against a freshly formatted FAT and littlefs filesystem.
// Every case below asserts identical behavior on both: that is the whole point
// of the portable flag conversion.
func eachBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	t.Helper()
	t.Run("fat", func(t *testing.T) { fn(t, newFATBackend(t)) })
	t.Run("lfs", func(t *testing.T) { fn(t, newLFSBackend(t)) })
}

// writeFile creates path with the given contents, failing the test on error.
func writeFile(t *testing.T, b backend, path, contents string) {
	t.Helper()
	f, err := b.open(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal("create:", err)
	}
	if _, err = f.WriteString(contents); err != nil {
		t.Fatal("write:", err)
	}
	if err = f.Close(); err != nil {
		t.Fatal("close:", err)
	}
}

// readAll reads path in full.
func readAll(t *testing.T, b backend, path string) string {
	t.Helper()
	f, err := b.open(path, os.O_RDONLY)
	if err != nil {
		t.Fatal("open for read:", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal("read:", err)
	}
	return string(got)
}

// TestOpenCreateExcl checks O_CREATE|O_EXCL fails on the second open, and that
// the failure is reportable through the standard fs.ErrExist sentinel.
func TestOpenCreateExcl(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		const path = "/excl.txt"
		f, err := b.open(path, os.O_RDWR|os.O_CREATE|os.O_EXCL)
		if err != nil {
			t.Fatal("first create:", err)
		}
		f.Close()

		_, err = b.open(path, os.O_RDWR|os.O_CREATE|os.O_EXCL)
		if err == nil {
			t.Fatal("second O_CREATE|O_EXCL open succeeded, want failure")
		}
		if !errors.Is(err, fs.ErrExist) {
			t.Errorf("second open error %v does not match fs.ErrExist", err)
		}
	})
}

// TestOpenCreatePreservesContents is the case that motivated exporting
// fat.ModeOpenAlways: a plain O_CREATE must create a missing file but leave an
// existing one's contents alone. Before that export, FAT could only reach
// ModeCreateAlways here, which truncates.
func TestOpenCreatePreservesContents(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		const path, contents = "/keep.txt", "hello world"
		writeFile(t, b, path, contents)

		f, err := b.open(path, os.O_WRONLY|os.O_CREATE)
		if err != nil {
			t.Fatal("O_CREATE on existing file:", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal("close:", err)
		}
		if got := readAll(t, b, path); got != contents {
			t.Errorf("O_CREATE truncated an existing file: got %q, want %q", got, contents)
		}
	})
}

// TestOpenTruncWithoutCreate covers the flag FAT has no mode bit for: O_TRUNC
// alone must empty an existing file (FATFS emulates this with a post-open
// Truncate) and must still fail on a missing one rather than creating it.
func TestOpenTruncWithoutCreate(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		const path = "/trunc.txt"
		writeFile(t, b, path, "some contents")

		f, err := b.open(path, os.O_WRONLY|os.O_TRUNC)
		if err != nil {
			t.Fatal("O_TRUNC on existing file:", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal("close:", err)
		}
		info, err := b.stat(path)
		if err != nil {
			t.Fatal("stat after truncate:", err)
		}
		if info.Size() != 0 {
			t.Errorf("O_TRUNC left size %d, want 0", info.Size())
		}

		if _, err = b.open("/missing.txt", os.O_WRONLY|os.O_TRUNC); err == nil {
			t.Error("O_TRUNC without O_CREATE created a missing file, want failure")
		}
	})
}

// TestOpenMissing checks a plain open of a missing file fails through the
// standard fs.ErrNotExist sentinel on both backends.
func TestOpenMissing(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		_, err := b.open("/nonexistent.txt", os.O_RDONLY)
		if err == nil {
			t.Fatal("open of missing file succeeded, want failure")
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("open error %v does not match fs.ErrNotExist", err)
		}
	})
}

// TestOpenAppendDoesNotCreate guards the subtle part of the FAT conversion:
// fat.ModeOpenAppend implicitly creates the file, so FATFS.mode deliberately
// does not use it. O_APPEND without O_CREATE must fail on a missing file, as it
// does on os and littlefs.
func TestOpenAppendDoesNotCreate(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		if _, err := b.open("/noappend.txt", os.O_WRONLY|os.O_APPEND); err == nil {
			t.Fatal("O_APPEND without O_CREATE created a missing file, want failure")
		}
		if _, err := b.stat("/noappend.txt"); err == nil {
			t.Error("O_APPEND without O_CREATE left a file behind on a failed open")
		}
	})
}

// TestOpenAppendWrites checks the shared part of append semantics: an O_APPEND
// handle starts positioned at the end, so a write extends rather than
// overwrites. The backends diverge once a caller Seeks on an append handle (see
// (*FATFS).mode), which is why that is not asserted here.
func TestOpenAppendWrites(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		const path = "/append.txt"
		writeFile(t, b, path, "head")

		f, err := b.open(path, os.O_WRONLY|os.O_APPEND)
		if err != nil {
			t.Fatal("open append:", err)
		}
		if _, err = f.WriteString("tail"); err != nil {
			t.Fatal("append write:", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal("close:", err)
		}
		if got := readAll(t, b, path); got != "headtail" {
			t.Errorf("append got %q, want %q", got, "headtail")
		}
	})
}

// TestOpenRejectsBadFlags checks the conversion rejects flags it cannot honor
// before touching the device, rather than silently dropping them.
func TestOpenRejectsBadFlags(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		for _, test := range []struct {
			name string
			flag int
		}{
			{"all access bits", os.O_RDONLY | os.O_WRONLY | os.O_RDWR},
			{"O_EXCL without O_CREATE", os.O_RDWR | os.O_EXCL},
			{"unsupported flag", os.O_RDWR | os.O_CREATE | os.O_SYNC},
		} {
			if _, err := b.open("/flags.txt", test.flag); err == nil {
				t.Errorf("%s: open succeeded, want rejection", test.name)
			}
		}
	})
}

// TestStatModeAgreesWithIsDir checks the fs.FileMode read back from a Stat is
// self-consistent, which is what the new lfs.FileInfo.Mode has to guarantee for
// *lfs.FileInfo to be a usable [filesystem.FileInfo].
func TestStatModeAgreesWithIsDir(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		writeFile(t, b, "/file.txt", "x")
		if err := b.mkdir("/dir"); err != nil {
			t.Fatal("mkdir:", err)
		}
		for path, wantDir := range map[string]bool{"/file.txt": false, "/dir": true} {
			info, err := b.stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if info.IsDir() != wantDir {
				t.Errorf("stat %s: IsDir() = %v, want %v", path, info.IsDir(), wantDir)
			}
			if info.Mode().IsDir() != info.IsDir() {
				t.Errorf("stat %s: Mode().IsDir() = %v disagrees with IsDir() = %v",
					path, info.Mode().IsDir(), info.IsDir())
			}
		}
	})
}
