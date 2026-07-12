package filesystem

import (
	"os"
	"testing"
)

// FuzzFlagConversion is the cheapest high-value target in the package, and it is
// in package filesystem rather than filesystem_test because the two functions it
// compares are unexported.
//
// (*FATFS).mode and (*LittleFS).openFlags are the subtlest code here: a bitmask
// conversion with an emulated O_TRUNC, an emulated O_APPEND, and a trap around
// fat.ModeOpenAppend that silently creates files. They are also stateless, so a
// fuzz iteration is a few nanoseconds — the engine gets through the whole 2^32
// flag space in the time the stateful targets need to format one device.
//
// The property is the package's headline promise reduced to its smallest form:
// a portable flag set is either supported by both backends or rejected by both.
// If one of them ever starts accepting a flag combination the other refuses, the
// abstraction has a hole in it, and a caller who switched backends would be
// getting a guarantee that silently evaporated.
func FuzzFlagConversion(f *testing.F) {
	// The combinations the hand-written tests already care about, plus the ones
	// that must be rejected.
	for _, seed := range []int{
		os.O_RDONLY,
		os.O_WRONLY,
		os.O_RDWR,
		os.O_RDWR | os.O_CREATE,
		os.O_RDWR | os.O_CREATE | os.O_EXCL,
		os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
		os.O_WRONLY | os.O_TRUNC,            // O_TRUNC without O_CREATE: emulated on FAT.
		os.O_WRONLY | os.O_APPEND,           // O_APPEND without O_CREATE: must not create.
		os.O_RDWR | os.O_EXCL,               // O_EXCL without O_CREATE: rejected.
		os.O_WRONLY | os.O_RDWR,             // Invalid access mode: rejected.
		os.O_RDWR | os.O_CREATE | os.O_SYNC, // Unsupported flag: rejected.
	} {
		f.Add(int64(seed))
	}

	var fatfs FATFS
	var lfs LittleFS
	f.Fuzz(func(t *testing.T, flag64 int64) {
		flag := int(flag64)

		_, postTrunc, postSeekEnd, fatErr := fatfs.mode(flag, 0)
		_, lfsErr := lfs.openFlags(flag, 0)

		if (fatErr == nil) != (lfsErr == nil) {
			t.Fatalf("flag %#x (%s): FAT error %v, littlefs error %v: the two backends "+
				"disagree on whether this flag set is supported, so the portable "+
				"abstraction leaks", flag, flagNames(flag), fatErr, lfsErr)
		}
		if fatErr != nil {
			return
		}

		// FAT emulates the two flags it has no mode bit for, after the open. The
		// fixups it asks for must correspond to the flags that were requested, and
		// only to those: a postTrunc on a flag set without O_TRUNC would silently
		// empty a file the caller asked to keep, and a missing one would leave a
		// file the caller asked to empty.
		if want := flag&os.O_TRUNC != 0 && flag&os.O_CREATE == 0; postTrunc != want {
			t.Errorf("flag %#x (%s): postTrunc = %v, want %v", flag, flagNames(flag), postTrunc, want)
		}
		if want := flag&os.O_APPEND != 0; postSeekEnd != want {
			t.Errorf("flag %#x (%s): postSeekEnd = %v, want %v", flag, flagNames(flag), postSeekEnd, want)
		}
	})
}

func flagNames(flag int) string {
	s := [...]string{"O_RDONLY", "O_WRONLY", "O_RDWR", "O_WRONLY|O_RDWR"}[flag&3]
	for _, f := range [...]struct {
		flag int
		name string
	}{
		{os.O_CREATE, "O_CREATE"}, {os.O_EXCL, "O_EXCL"}, {os.O_TRUNC, "O_TRUNC"},
		{os.O_APPEND, "O_APPEND"}, {os.O_SYNC, "O_SYNC"},
	} {
		if flag&f.flag != 0 {
			s += "|" + f.name
		}
	}
	return s
}
