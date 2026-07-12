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

// This file pins the bugs the fuzzer in fsfuzz found, and that neither this
// package nor its backends currently fix. Each is a hole in the portability
// [filesystem] exists to provide: FAT and littlefs disagree, and in every case
// exactly one of them also disagrees with [os.File], which is the semantics this
// package models itself on.
//
//	behavior                             FAT           littlefs      os.File
//	Read/ReadAt on an O_WRONLY handle    denied        RETURNS DATA  EBADF
//	Seek past EOF, writable handle       GROWS FILE    no change     no change
//	Seek past EOF, read-only handle      CLIPS TO EOF  seeks there   seeks there
//	Truncate with the offset past it     MOVES OFFSET  no change     no change
//	Reading a hole                       RAW MEDIA     zeros         zeros
//
// These tests assert the WRONG behavior on purpose. That is what makes them
// useful: they are the tripwire on the quarantine flags in [fsfuzz.Caps], which
// tell the fuzzer to stop reporting these so it can go looking for the next one.
// Fix one of the bugs and the test for it fails — which is the signal to delete
// the test and its quarantine flag together, and to let the fuzzer start
// enforcing the correct behavior instead.
//
// Do not "fix" a failure here by updating the assertion.

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

// eachFAT runs fn as a subtest against both FAT variants.
//
// Both, because they are only the same driver above the FAT itself: FAT32 chains
// clusters through a 32-bit table and keeps its root directory in one of those
// chains, while exFAT has an allocation bitmap and a fixed root. Every bug pinned
// in this file is in the file layer, above where the two part ways — running both
// is what establishes that, and it is what would catch a fix that landed in one
// variant and not the other.
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

// TestDivergenceReadIgnoresAccessMode pins the littlefs bug behind
// [fsfuzz.Caps.ReadIgnoresAccessMode].
//
// lfs.File.Write refuses a handle that lacks the write bit, but neither
// lfs.File.Read nor lfs.File.ReadAt checks the read bit — lfs.FS.fileRead goes
// straight to fileFlushedread. The C source guards it with
// LFS_ASSERT((file->flags & LFS_O_RDONLY) == LFS_O_RDONLY); the Go port dropped
// the assert and never replaced it with an error return, so the check is gone in
// one direction and present in the other. FAT gets it right: fat's f_read
// returns frDenied when fp.flag&faRead is clear.
func TestDivergenceReadIgnoresAccessMode(t *testing.T) {
	const contents = "hello"
	read := func(t *testing.T, fsys *filesystem.FS) (viaRead, viaReadAt []byte, readErr, readAtErr error) {
		t.Helper()
		f, err := fsys.OpenFile("/a", os.O_WRONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		defer f.Close()
		if _, err = f.WriteString(contents); err != nil {
			t.Fatal("write:", err)
		}
		buf := make([]byte, len(contents))
		n, readAtErr := f.ReadAt(buf, 0)
		viaReadAt = append([]byte(nil), buf[:n]...)

		if _, err = f.Seek(0, io.SeekStart); err != nil {
			t.Fatal("seek:", err)
		}
		clear(buf)
		n, readErr = f.Read(buf)
		viaRead = append([]byte(nil), buf[:n]...)
		return viaRead, viaReadAt, readErr, readAtErr
	}

	eachFAT(t, "fat refuses, which is correct", func(t *testing.T, fsys *filesystem.FS) {
		_, _, readErr, readAtErr := read(t, fsys)
		if readErr == nil {
			t.Error("Read through an O_WRONLY handle succeeded")
		}
		if readAtErr == nil {
			t.Error("ReadAt through an O_WRONLY handle succeeded")
		}
	})

	t.Run("littlefs hands back the data, which is the bug", func(t *testing.T) {
		h := fsfuzz.GetLittle()
		defer h.Release()
		fsys := h.FS()
		viaRead, viaReadAt, readErr, readAtErr := read(t, fsys)
		// Asserting the bug. When lfs.FS.fileRead learns to check the read bit,
		// these fail: delete this subtest and clear Caps.ReadIgnoresAccessMode.
		if readErr != nil || string(viaRead) != contents {
			t.Fatalf("littlefs now refuses Read on an O_WRONLY handle (got %q, %v). "+
				"The bug is fixed: delete this test and clear fsfuzz.Caps.ReadIgnoresAccessMode "+
				"so the fuzzer starts enforcing the refusal.", viaRead, readErr)
		}
		if readAtErr != nil || string(viaReadAt) != contents {
			t.Fatalf("littlefs now refuses ReadAt on an O_WRONLY handle (got %q, %v). "+
				"The bug is fixed: delete this test and clear fsfuzz.Caps.ReadIgnoresAccessMode.",
				viaReadAt, readAtErr)
		}
	})
}

// TestDivergenceSeekBoundedBySize pins the FAT bug behind
// [fsfuzz.Caps.SeekBoundedBySize].
//
// FatFs f_lseek refuses to let the file position exceed the file size, and hides
// that in two different and mutually incompatible ways:
//
//   - On a WRITABLE handle it extends the file out to the requested offset. The
//     seek alone changes the size, and it does so by allocating clusters, so a
//     plain Seek can also fail on a full device.
//
//   - On a READ-ONLY handle it clips the seek back to the end of the file and
//     reports the clipped offset as though the seek had done what was asked. A
//     caller that seeks to 48 in an empty file is told it is at 0.
//
// os and littlefs do neither. Seeking past the end is free, the position goes
// where it was put, and the hole appears only when something writes into it.
func TestDivergenceSeekBoundedBySize(t *testing.T) {
	const initial = "hello"
	const seekTo = 4096

	// sizeAfterWritableSeek is the write-mode half: does the seek grow the file?
	sizeAfterWritableSeek := func(t *testing.T, fsys *filesystem.FS) int64 {
		t.Helper()
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
		return info.Size()
	}

	// offsetAfterReadOnlySeek is the read-mode half: is the seek clipped to EOF?
	offsetAfterReadOnlySeek := func(t *testing.T, fsys *filesystem.FS) int64 {
		t.Helper()
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
		return off
	}

	eachFAT(t, "fat grows a writable file, which is the bug", func(t *testing.T, fsys *filesystem.FS) {
		if got := sizeAfterWritableSeek(t, fsys); got != seekTo {
			t.Fatalf("FAT no longer grows a file on a seek past EOF: size %d, want %d. "+
				"If the fix was intentional, delete this test and clear "+
				"fsfuzz.Caps.SeekBoundedBySize.", got, seekTo)
		}
	})

	eachFAT(t, "fat clips a read-only seek, which is the bug", func(t *testing.T, fsys *filesystem.FS) {
		if got := offsetAfterReadOnlySeek(t, fsys); got != int64(len(initial)) {
			t.Fatalf("FAT no longer clips a read-only seek past EOF: offset %d, want %d "+
				"(the clipped size). If the fix was intentional, delete this test and "+
				"clear fsfuzz.Caps.SeekBoundedBySize.", got, len(initial))
		}
	})

	t.Run("littlefs does neither, which is correct", func(t *testing.T) {
		h := fsfuzz.GetLittle()
		defer h.Release()
		fsys := h.FS()
		if got, want := sizeAfterWritableSeek(t, fsys), int64(len(initial)); got != want {
			t.Errorf("seek past EOF changed the size to %d, want %d", got, want)
		}
		if got := offsetAfterReadOnlySeek(t, fsys); got != seekTo {
			t.Errorf("read-only seek past EOF landed at %d, want %d", got, seekTo)
		}
	})
}

// TestDivergenceHolesAreGarbage pins the FAT bug behind
// [fsfuzz.Caps.HolesAreGarbage], which is the most serious thing the fuzzer has
// found here and the only one that is not merely a portability wart.
//
// FatFs grows a file by allocating clusters and does not erase them, so the hole
// reads back as whatever was on the media. On the RAM device this test uses that
// is the 0xff of erased flash and nothing is at stake. On a real part it is
// whatever those blocks last held — which, on a filesystem that has ever deleted
// a file, is the contents of that file. A program that creates a file, seeks
// past the end and reads back gets handed data it never wrote and was never
// given.
//
// os zero-fills a hole. littlefs zero-fills a hole. This does not.
func TestDivergenceHolesAreGarbage(t *testing.T) {
	const hole = 4096

	// holeByte reads the first byte of a hole created by seeking past the end.
	holeByte := func(t *testing.T, fsys *filesystem.FS) byte {
		t.Helper()
		f, err := fsys.OpenFile("/a", os.O_RDWR|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal("create:", err)
		}
		defer f.Close()
		if _, err = f.Seek(hole, io.SeekStart); err != nil {
			t.Fatal("seek:", err)
		}
		// Anchor the file at the far side of the hole so both backends agree there
		// is a file here at all, then read back what is in the middle of it.
		if _, err = f.WriteString("x"); err != nil {
			t.Fatal("write:", err)
		}
		buf := make([]byte, 1)
		if _, err = f.ReadAt(buf, 0); err != nil {
			t.Fatal("readat:", err)
		}
		return buf[0]
	}

	eachFAT(t, "fat hands back the media, which is the bug", func(t *testing.T, fsys *filesystem.FS) {
		if got := holeByte(t, fsys); got == 0x00 {
			t.Fatalf("FAT now zero-fills a hole. The bug is fixed: delete this test "+
				"and clear fsfuzz.Caps.HolesAreGarbage so the fuzzer starts enforcing "+
				"the zero-fill. (got %#02x)", got)
		}
	})

	t.Run("littlefs zero-fills, which is correct", func(t *testing.T) {
		h := fsfuzz.GetLittle()
		defer h.Release()
		if got := holeByte(t, h.FS()); got != 0x00 {
			t.Errorf("littlefs read %#02x out of a hole, want 0x00: a hole must not "+
				"expose the contents of the device", got)
		}
	})
}

// TestDivergenceAppendMovesReadOffset pins the FAT bug behind
// [fsfuzz.Caps.AppendPerWrite], which the fuzzer found on a five-operation
// program nobody would have thought to write:
//
//	open "/a" O_WRONLY|O_CREATE|O_APPEND; write 45; close
//	open "/a" O_RDONLY|O_APPEND;          read  48   <- FAT says EOF
//
// POSIX is explicit that O_APPEND governs writes: "the file offset shall be set
// to the end of the file prior to each write". It says nothing about reads, and
// an O_APPEND handle starts at offset zero like any other. littlefs, which has a
// native append, does exactly that.
//
// FAT has no native append this package can use — fat.ModeOpenAppend implies
// create, which O_APPEND must not — so (*FATFS).OpenFile emulates one by seeking
// to the end at open. That seek moves the read offset too, so a file opened for
// reading with O_APPEND is positioned at its own end and reads EOF forever. The
// caller is handed an empty file that is not empty.
func TestDivergenceAppendMovesReadOffset(t *testing.T) {
	const contents = "the file you will not be shown"

	// firstRead writes a file, reopens it O_RDONLY|O_APPEND, and reads. POSIX says
	// this returns the contents.
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
	t.Run("os returns the contents, which is the standard", func(t *testing.T) {
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
			t.Fatalf("os.File read %q, %v through an O_RDONLY|O_APPEND handle; want the "+
				"contents. If this fails, the premise of this whole test is wrong.",
				buf[:n], err)
		}
	})

	eachFAT(t, "fat reads EOF, which is the bug", func(t *testing.T, fsys *filesystem.FS) {
		got, err := firstRead(t, fsys)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("FAT no longer positions an O_APPEND handle at EOF for reading: read "+
				"%q, %v. The bug is fixed: drop the open-time seek from the model in "+
				"fsfuzz.model.wantOpen and delete this test.", got, err)
		}
	})

	t.Run("littlefs returns the contents, which is correct", func(t *testing.T) {
		h := fsfuzz.GetLittle()
		defer h.Release()
		got, err := firstRead(t, h.FS())
		if err != nil || got != contents {
			t.Errorf("littlefs read %q, %v through an O_RDONLY|O_APPEND handle, want the "+
				"contents: O_APPEND must not move the read offset", got, err)
		}
	})
}

// TestAppendMovesOnlyBackwards is not a divergence but a subtlety that cost this
// harness two fuzz findings before it was modeled right, so it is pinned.
//
// littlefs is a true POSIX append: it seeks to the end before every write. But
// lfs_file_write guards that move with (file->pos < file->ctz.size), so it only
// drags the position FORWARD to the end — a handle deliberately seeked PAST the
// end writes where it was left, sparsely, and is not pulled back. Anyone
// reasoning about O_APPEND as "always writes at the end" gets this wrong.
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

// TestDivergenceTruncateMovesOffset pins the FAT bug behind
// [fsfuzz.Caps.TruncateMovesOffset].
//
// FAT clamps the file pointer to the new size on truncate. os and littlefs leave
// it where the caller put it, so a caller who truncates and then writes puts the
// bytes at the offset they chose — into the hole — rather than silently at the
// new end of the file.
func TestDivergenceTruncateMovesOffset(t *testing.T) {
	const wrote, truncTo = 1000, 255

	offsetAfterTruncate := func(t *testing.T, fsys *filesystem.FS) int64 {
		t.Helper()
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
		return off
	}

	eachFAT(t, "fat moves the offset, which is the bug", func(t *testing.T, fsys *filesystem.FS) {
		if got := offsetAfterTruncate(t, fsys); got != truncTo {
			t.Fatalf("FAT no longer clamps the offset on truncate: offset %d, want %d. "+
				"If the fix was intentional, delete this test and clear "+
				"fsfuzz.Caps.TruncateMovesOffset.", got, truncTo)
		}
	})

	t.Run("littlefs leaves it alone, which is correct", func(t *testing.T) {
		h := fsfuzz.GetLittle()
		defer h.Release()
		fsys := h.FS()
		if got := offsetAfterTruncate(t, fsys); got != wrote {
			t.Errorf("truncate moved the offset to %d, want %d", got, wrote)
		}
	})
}

// TestPortableErrorsAgree is not a divergence test but the guard that would have
// caught the read-permission hole years earlier: the errors both backends report
// for the same portable mistake must be reportable the same way. It is the
// property FuzzFlagConversion checks for flags, applied to paths.
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
