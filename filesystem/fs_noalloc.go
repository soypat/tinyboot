package filesystem

import (
	"errors"
	"io/fs"
	"os"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
)

var (
	_ FSNoAlloc[*fat.File, *fat.Dir, *fat.FileInfo] = (*FATFS)(nil)
	_ FSNoAlloc[*lfs.File, *lfs.Dir, *lfs.FileInfo] = (*LittleFS)(nil)
)

var (
	errBadAccessMode   = errors.New("filesystem: invalid access mode, want one of O_RDONLY, O_WRONLY, O_RDWR")
	errUnsupportedFlag = errors.New("filesystem: unsupported open flag")
	errExclNoCreate    = errors.New("filesystem: O_EXCL without O_CREATE")
)

// supportedFlags is the set of os.O_* bits either backend can honor. Any other
// bit (O_SYNC, O_NOFOLLOW, O_DIRECTORY...) is rejected by the conversion methods
// rather than silently dropped, so that a caller never believes it got a
// guarantee the backend cannot provide.
const supportedFlags = os.O_RDONLY | os.O_WRONLY | os.O_RDWR |
	os.O_CREATE | os.O_EXCL | os.O_TRUNC | os.O_APPEND

var (
	_ FileHandle = (*fat.File)(nil)
	_ FileHandle = (*lfs.File)(nil)
	_ FileHandle = (*os.File)(nil)
)

type FileInfo interface {
	fs.FileInfo
	AppendName(dst []byte) []byte
}

// FileHandle is an open file. Callers own the storage: handles are passed into
// OpenFile by pointer and filled in, so no allocation occurs on open.
type FileHandle interface {
	Close() error
	Read(buf []byte) (int, error)
	ReadAt(p []byte, off int64) (int, error)
	Seek(offset int64, whence int) (int64, error)
	Sync() error
	Truncate(size int64) error
	Write(buf []byte) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	WriteString(s string) (int, error)
}

// DirHandle is an open directory, iterated by callback rather than by returning
// a slice so that listing a directory does not allocate.
type DirHandle[I FileInfo] interface {
	Close() error
	Rewind() error
	ReadNext(finfo I) error
	ForEachFile(cb func(I) error) error
}

// FSNoAlloc is a mounted filesystem. The directory handle type D is a separate type
// parameter from the info type I so that OpenDir receives the backend's concrete
// directory type; taking a DirHandle[I] interface here would force every
// implementation into a type assertion to recover it.
//
// Mounting is not part of this interface: fat and lfs take different geometry
// (fat needs a sector size, lfs needs a page size and an erase block size), and
// no useful abstraction spans the two. Mount the native FSNoAlloc, then wrap it.
type FSNoAlloc[F FileHandle, D DirHandle[I], I FileInfo] interface {
	// OpenFile mirrors [os.OpenFile]: flag is a bitmask of the os.O_* constants
	// and perm is ignored (see the package documentation).
	OpenFile(f F, path string, flag int, perm fs.FileMode) error
	OpenDir(d D, path string) error
	Mkdir(path string) error
	Remove(path string) error
	Rename(oldpath, newpath string) error
	Stat(path string, info I) error
}

// access splits the low two bits of flag, which hold the access mode. os.O_RDONLY
// is zero, so a flag of 0 means read-only exactly as it does in [os.OpenFile].
func access(flag int) (read, write bool, err error) {
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		return true, false, nil
	case os.O_WRONLY:
		return false, true, nil
	case os.O_RDWR:
		return true, true, nil
	}
	return false, false, errBadAccessMode
}
