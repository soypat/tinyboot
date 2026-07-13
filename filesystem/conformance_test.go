package filesystem_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/soypat/tinyboot/filesystem"
	"github.com/soypat/tinyboot/filesystem/fsfuzz"
)

// This file is the POSIX conformance suite for the backends, and every test in
// it started life as the opposite: a test asserting a BUG, on purpose, to pin a
// divergence the fuzzer in fsfuzz had found and that had been quarantined behind
// a flag in [fsfuzz.Caps] so the fuzzer would stop re-reporting it and get on
// with looking for the next one.
//
//	behavior                             FAT was        littlefs was   os.File
//	Read/ReadAt on an O_WRONLY handle    denied         RETURNED DATA  EBADF
//	Seek past EOF, writable handle       GREW THE FILE  no change      no change
//	Seek past EOF, read-only handle      CLIPPED TO EOF seeks there    seeks there
//	Truncate with the offset past it     MOVED OFFSET   no change      no change
//	Reading a hole                       RAW MEDIA      zeros          zeros
//	Read on a fresh O_RDONLY|O_APPEND    EOF            reads from 0   reads from 0
//
// All six are fixed, upstream in soypat/fat and soypat/lfs, so each test was
// turned around to assert the behavior POSIX asks for. The quarantine flags are
// gone with them, which means the model in fsfuzz now enforces all of this on
// every operation of every fuzz program, rather than looking the other way.
//
// The os.File arms are the point of the exercise and are worth keeping: they are
// what established which side of each disagreement was wrong, rather than which
// side was outnumbered.

// eachPooledFS runs fn against every freshly formatted backend. The devices come
// from the fsfuzz free list rather than being allocated here, so a test that runs
// a thousand times does not allocate a thousand devices.
func eachPooledFS(t *testing.T, fn func(t *testing.T, fsys *filesystem.FS)) {
	t.Helper()
	for _, backend := range []struct {
		name string
		get  func() *fsfuzz.Harness
	}{
		{"fat32", fsfuzz.GetFAT32},
		{"exfat", fsfuzz.GetExFAT},
		{"lfs", fsfuzz.GetLittle},
	} {
		t.Run(backend.name, func(t *testing.T) {
			h := backend.get()
			defer h.Release()
			fn(t, h.FS())
		})
	}
}

// TestReadRequiresReadAccess: littlefs used to hand back the file through a
// handle opened os.O_WRONLY. lfs.File.Write refused a handle without the write
// bit, but neither Read nor ReadAt checked the read bit — the C library guards
// lfs_file_read with LFS_ASSERT((file->flags & LFS_O_WRONLY) != LFS_O_WRONLY), so
// it means to reject it, but an assert compiles out of a release build and does
// not survive a port to Go at all. Fixed in soypat/lfs.
func TestReadRequiresReadAccess(t *testing.T) {
	const contents = "the file you will not be shown"

	eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
		f, err := fsys.OpenFile("/a", os.O_WRONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		defer f.Close()
		if _, err = f.WriteString(contents); err != nil {
			t.Fatal("write:", err)
		}

		buf := make([]byte, len(contents))
		if n, err := f.ReadAt(buf, 0); err == nil {
			t.Errorf("ReadAt through an O_WRONLY handle returned %d bytes (%q) and no error", n, buf[:n])
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			t.Fatal("seek:", err)
		}
		clear(buf)
		if n, err := f.Read(buf); err == nil {
			t.Errorf("Read through an O_WRONLY handle returned %d bytes (%q) and no error", n, buf[:n])
		}
	})
}

// TestSeekPastEndIsFree: a seek is not a write. FatFs f_lseek refused to let the
// position exceed the file size and hid that in two mutually incompatible ways —
// on a writable handle it EXTENDED the file out to the requested offset (so a
// plain Seek allocated clusters and could fail on a full device), and on a
// read-only handle it CLIPPED the seek back to the end and reported the clipped
// offset as though the seek had done what was asked, telling a caller who seeked
// to 4096 in a 5 byte file that it was at 5. Fixed in soypat/fat.
func TestSeekPastEndIsFree(t *testing.T) {
	const initial = "hello"
	const seekTo = 4096

	t.Run("a writable seek does not grow the file", func(t *testing.T) {
		eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
			f, err := fsys.OpenFile("/a", os.O_RDWR|os.O_CREATE, 0o666)
			if err != nil {
				t.Fatal("create:", err)
			}
			if _, err = f.WriteString(initial); err != nil {
				t.Fatal("write:", err)
			}
			if _, err = f.Seek(seekTo, io.SeekStart); err != nil {
				t.Fatal("seek:", err)
			}
			if err = f.Close(); err != nil {
				t.Fatal("close:", err)
			}
			info, err := fsys.Stat("/a")
			if err != nil {
				t.Fatal("stat:", err)
			}
			if info.Size() != int64(len(initial)) {
				t.Errorf("a seek past EOF grew the file to %d bytes, want %d: seeking must not "+
					"change the file", info.Size(), len(initial))
			}
		})
	})

	t.Run("a read-only seek is not clipped", func(t *testing.T) {
		eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
			f, err := fsys.OpenFile("/b", os.O_RDWR|os.O_CREATE, 0o666)
			if err != nil {
				t.Fatal("create:", err)
			}
			if _, err = f.WriteString(initial); err != nil {
				t.Fatal("write:", err)
			}
			f.Close()

			f, err = fsys.OpenFile("/b", os.O_RDONLY, 0o666)
			if err != nil {
				t.Fatal("reopen read-only:", err)
			}
			defer f.Close()
			off, err := f.Seek(seekTo, io.SeekStart)
			if err != nil {
				t.Fatal("seek:", err)
			}
			if off != seekTo {
				t.Errorf("a read-only seek past EOF landed at %d, want %d: it was clipped to the "+
					"end of the file and reported as though it had succeeded", off, seekTo)
			}
			if n, err := f.Read(make([]byte, 8)); err != io.EOF {
				t.Errorf("Read past EOF = %d, %v; want 0, io.EOF", n, err)
			}
		})
	})
}

// TestHolesAreZeroFilled is the one that mattered.
//
// FAT has no sparse files: a file is a size plus a chain of clusters, and every
// byte inside the size is file content. FatFs grew a file by linking clusters and
// never erasing them, so the bytes a file grew over — which nobody wrote — read
// back as whatever the media last held. On a volume that has ever deleted a file,
// that is the deleted file's contents, handed to a caller who never wrote them
// and was never given them.
//
// Fixed in soypat/fat, which now zero-fills the gap by default, as POSIX and the
// Windows FAT driver do. FatFs' bytes remain available, deliberately and by name,
// through fat.FSConfig.NoZeroFilling.
func TestHolesAreZeroFilled(t *testing.T) {
	const hole = 4096

	eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
		f, err := fsys.OpenFile("/a", os.O_RDWR|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		defer f.Close()
		if _, err = f.Seek(hole, io.SeekStart); err != nil {
			t.Fatal("seek:", err)
		}
		// Anchor the file at the far side of the hole, then read back the middle.
		if _, err = f.WriteString("x"); err != nil {
			t.Fatal("write:", err)
		}
		buf := make([]byte, hole)
		if _, err = f.ReadAt(buf, 0); err != nil {
			t.Fatal("readat:", err)
		}
		for i, b := range buf {
			if b != 0 {
				t.Fatalf("byte %d of a hole reads %#02x, want 0: a hole must not expose the "+
					"contents of the device", i, b)
			}
		}
	})
}

// TestTruncateDoesNotMoveOffset: POSIX ftruncate leaves the file offset where the
// caller put it, even when that is past the new end of the file. FAT used to clamp
// it down to the new size, so a caller who truncated and then wrote found the
// bytes silently at the new end rather than at the offset they chose. Fixed in
// soypat/fat.
func TestTruncateDoesNotMoveOffset(t *testing.T) {
	const wrote, truncTo = 1000, 255

	eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
		f, err := fsys.OpenFile("/a", os.O_RDWR|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		defer f.Close()
		if _, err = f.Write(make([]byte, wrote)); err != nil {
			t.Fatal("write:", err)
		}
		if err = f.Truncate(truncTo); err != nil {
			t.Fatal("truncate:", err)
		}
		off, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			t.Fatal("seek:", err)
		}
		if off != wrote {
			t.Errorf("truncate moved the offset to %d, want %d: it must leave the offset alone",
				off, wrote)
		}
	})
}

// TestAppendDoesNotMoveReadOffset: POSIX is explicit that O_APPEND governs writes
// — "the file offset shall be set to the end of the file prior to each write" —
// and says nothing about reads, so an O_APPEND handle starts at offset zero like
// any other.
//
// FAT has no native append this package can use (fat.ModeOpenAppend implies
// create, which O_APPEND must not), so (*FATFS).OpenFile used to emulate one by
// seeking to the end at open. That seek moved the READ offset too, so a file
// opened O_RDONLY|O_APPEND sat at its own end and read EOF forever: the caller
// was handed an empty file that was not empty. It took a five-operation program
// from the fuzzer to find, and nobody would have sat down to write that test.
//
// Fixed in this package: append is emulated per write, in [filesystem.File].
func TestAppendDoesNotMoveReadOffset(t *testing.T) {
	const contents = "the file you will not be shown"

	firstRead := func(t *testing.T, fsys *filesystem.FS) (string, error) {
		t.Helper()
		f, err := fsys.OpenFile("/a", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		if _, err = f.WriteString(contents); err != nil {
			t.Fatal("write:", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal("close:", err)
		}

		f, err = fsys.OpenFile("/a", os.O_RDONLY|os.O_APPEND, 0o666)
		if err != nil {
			t.Fatal("reopen:", err)
		}
		defer f.Close()
		buf := make([]byte, len(contents))
		n, err := f.Read(buf)
		return string(buf[:n]), err
	}

	// os.File is the reference, so ask it rather than assert from memory.
	t.Run("os", func(t *testing.T) {
		path := t.TempDir() + "/a"
		if err := os.WriteFile(path, []byte(contents), 0o666); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_RDONLY|os.O_APPEND, 0o666)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		buf := make([]byte, len(contents))
		n, err := f.Read(buf)
		if err != nil || string(buf[:n]) != contents {
			t.Fatalf("os.File read %q, %v through an O_RDONLY|O_APPEND handle; want the contents. "+
				"If this fails, the premise of this whole test is wrong.", buf[:n], err)
		}
	})

	eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
		got, err := firstRead(t, fsys)
		if err != nil || got != contents {
			t.Errorf("read %q, %v through an O_RDONLY|O_APPEND handle, want the contents: "+
				"O_APPEND must not move the read offset", got, err)
		}
	})
}

// TestAppendWritesAtEnd: every write on an O_APPEND handle goes to the end of the
// file, wherever the caller left the offset. FAT's old emulation seeked to the end
// once, at open, so an intervening Seek stuck and the write landed where the
// caller had seeked — overwriting data that os would have appended after.
//
// Not run against littlefs: see TestAppendMovesOnlyBackwards.
func TestAppendWritesAtEnd(t *testing.T) {
	eachFAT(t, "a seek does not move an append write", func(t *testing.T, fsys *filesystem.FS) {
		f, err := fsys.OpenFile("/a", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		defer f.Close()
		if _, err = f.WriteString("head"); err != nil {
			t.Fatal("write:", err)
		}
		// Seek back to the start. The next write must still append.
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			t.Fatal("seek:", err)
		}
		if _, err = f.WriteString("tail"); err != nil {
			t.Fatal("write:", err)
		}
		buf := make([]byte, len("headtail"))
		n, err := f.ReadAt(buf, 0)
		if err != nil && err != io.EOF {
			t.Fatal("readat:", err)
		}
		if got := string(buf[:n]); got != "headtail" {
			t.Errorf("after seeking to 0 and writing on an O_APPEND handle the file is %q, "+
				"want %q: the write overwrote the file instead of appending to it", got, "headtail")
		}
	})
}

// eachFAT runs fn as a subtest against both FAT variants.
//
// Both, because they are only the same driver above the FAT itself: FAT32 chains
// clusters through a 32-bit table and keeps its root directory in one of those
// chains, while exFAT has an allocation bitmap and a fixed root. Every bug this
// file records lived in the file layer, above where the two part ways — running
// both is what established that, and it is what would catch a fix that landed in
// one variant and not the other.
func eachFAT(t *testing.T, name string, fn func(t *testing.T, fsys *filesystem.FS)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		for _, variant := range []struct {
			name string
			get  func() *fsfuzz.Harness
		}{
			{"fat32", fsfuzz.GetFAT32},
			{"exfat", fsfuzz.GetExFAT},
		} {
			t.Run(variant.name, func(t *testing.T) {
				h := variant.get()
				defer h.Release()
				fn(t, h.FS())
			})
		}
	})
}

// TestAppendMovesOnlyBackwards is the one divergence still standing, and it is
// littlefs's, faithfully ported rather than introduced.
//
// littlefs seeks an append handle to the end before every write — but
// lfs_file_write guards the move with (file->pos < file->ctz.size), so it only
// drags the position FORWARD to the end. A handle deliberately seeked PAST the
// end writes where it was left, sparsely, and is not pulled back. POSIX says the
// write always goes to the end.
//
// Left alone on purpose: fixing it means diverging from the C library for a case
// you have to go out of your way to reach. It is modeled instead, by
// fsfuzz.Caps.AppendForwardOnly, so the fuzzer holds littlefs to littlefs's
// semantics and FAT to POSIX's, and neither gets a free pass.
func TestAppendMovesOnlyBackwards(t *testing.T) {
	h := fsfuzz.GetLittle()
	defer h.Release()
	fsys := h.FS()

	f, err := fsys.OpenFile("/a", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o666)
	if err != nil {
		t.Fatal("create:", err)
	}
	const seekTo = 4096
	if _, err = f.Seek(seekTo, io.SeekStart); err != nil {
		t.Fatal("seek:", err)
	}
	if _, err = f.WriteString("tail"); err != nil {
		t.Fatal("write:", err)
	}
	if err = f.Close(); err != nil {
		t.Fatal("close:", err)
	}

	info, err := fsys.Stat("/a")
	if err != nil {
		t.Fatal("stat:", err)
	}
	if want := int64(seekTo + len("tail")); info.Size() != want {
		t.Errorf("append write after a seek past EOF produced a %d byte file, want %d: "+
			"the write was dragged back to the end of the file instead of landing "+
			"where the handle was seeked", info.Size(), want)
	}
}

// TestPortableErrorsAgree is the guard that would have caught the read-permission
// hole years earlier: the errors both backends report for the same portable
// mistake must be reportable the same way. It is the property FuzzFlagConversion
// checks for flags, applied to paths.
func TestPortableErrorsAgree(t *testing.T) {
	eachPooledFS(t, func(t *testing.T, fsys *filesystem.FS) {
		if _, err := fsys.Open("/missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("open of a missing file: %v, want fs.ErrNotExist", err)
		}
		if _, err := fsys.Stat("/missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stat of a missing file: %v, want fs.ErrNotExist", err)
		}
		if err := fsys.Remove("/missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("remove of a missing file: %v, want fs.ErrNotExist", err)
		}
		if err := fsys.Mkdir("/missing/deep"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("mkdir under a missing parent: %v, want fs.ErrNotExist", err)
		}
		f, err := fsys.Create("/exists")
		if err != nil {
			t.Fatal("create:", err)
		}
		f.Close()
		if err := fsys.Mkdir("/exists"); !errors.Is(err, fs.ErrExist) {
			t.Errorf("mkdir over an existing file: %v, want fs.ErrExist", err)
		}
		if _, err := fsys.OpenFile("/exists", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666); !errors.Is(err, fs.ErrExist) {
			t.Errorf("O_EXCL over an existing file: %v, want fs.ErrExist", err)
		}
	})
}
