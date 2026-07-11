// Package filesystem provides a portable, allocation-free interface over the
// embedded filesystem implementations in [github.com/soypat/fat] and
// [github.com/soypat/lfs], with open semantics modelled on [os.OpenFile].
//
// # Modes, flags and fs.FileMode
//
// The two libraries and the standard library split file state across two
// different axes, and conflating them is the single easiest mistake to make here:
//
//   - Open intent — create, exclusive, truncate, append — is what [fat.Mode] and
//     [lfs.OpenFlags] encode. In the standard library this lives in the flag
//     argument of [os.OpenFile], a bitmask of the os.O_* constants. It does NOT
//     live in [fs.FileMode]. This package therefore takes flag int and converts,
//     via (*FATFS).mode and (*LittleFS).openFlags, which document exactly what
//     each backend can and cannot represent.
//
//   - File metadata — type bits and permission bits — is what [fs.FileMode]
//     encodes. It is what you read back from a [fs.FileInfo], not something you
//     pass to an open call.
//
// The conversion is therefore one-way in this package: portable flags to native
// modes. The reverse direction (native to [fs.FileMode]) is not implemented here
// because it already exists upstream as fat.FileInfo.Mode and lfs.FileInfo.Mode.
// Both are synthetic to a degree — see those methods.
//
// Neither backend stores POSIX permissions, so the perm argument is accepted for
// symmetry with [os.OpenFile] and ignored. See the conversion methods for the
// full accounting of what a portable open call costs on each backend.
package filesystem

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
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
type DirHandle[I fs.FileInfo] interface {
	Close() error
	ForEachFile(cb func(info I) (earlyRetErr error)) error
}

var (
	_ FSNoAlloc[*fat.File, *fat.Dir, *fat.FileInfo] = (*FATFS)(nil)
	_ FSNoAlloc[*lfs.File, *lfs.Dir, *lfs.FileInfo] = (*LittleFS)(nil)
)

// FSNoAlloc is a mounted filesystem. The directory handle type D is a separate type
// parameter from the info type I so that OpenDir receives the backend's concrete
// directory type; taking a DirHandle[I] interface here would force every
// implementation into a type assertion to recover it.
//
// Mounting is not part of this interface: fat and lfs take different geometry
// (fat needs a sector size, lfs needs a page size and an erase block size), and
// no useful abstraction spans the two. Mount the native FSNoAlloc, then wrap it.
type FSNoAlloc[F FileHandle, D DirHandle[I], I fs.FileInfo] interface {
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

// Wrapped so that a caller can detect use-after-close with the standard
// errors.Is(err, fs.ErrClosed), as they would with an *os.File.
var (
	errFileClosed = fmt.Errorf("filesystem: use of closed file: %w", fs.ErrClosed)
	errDirClosed  = fmt.Errorf("filesystem: use of closed directory: %w", fs.ErrClosed)
)

// FS is the convenient counterpart of [FSNoAlloc]: it owns the handle storage
// that FSNoAlloc makes the caller provide, so opens return a ready handle rather
// than filling one in. Handles come from a [sync.Pool] and are returned to it on
// Close, so a program that closes what it opens allocates only up to its peak
// number of concurrently open files and directories, then never again. On TinyGo
// that pool is a plain free list which never shrinks, making the steady-state
// footprint bounded by that peak.
//
// FS must not be copied after first use, as it contains a [sync.Pool].
//
// Stat is the one operation that must still allocate. An [fs.FileInfo] has no
// Close, so nothing can ever hand it back, and there is no safe moment to
// recycle it.
type FS[F FileHandle, D DirHandle[I], I fs.FileInfo] struct {
	fs      FSNoAlloc[F, D, I]
	files   sync.Pool // of *File[F], each with its handle already allocated.
	dirs    sync.Pool // of *Dir[D, I], likewise.
	newInfo func() I
}

// NewFS wraps a mounted [FSNoAlloc] with handle pools. The three constructors
// say how to allocate a backend handle when a pool is empty; they also let the
// compiler infer F, D and I, which it cannot do from fsys alone because those
// parameters appear only inside an interface.
//
// Prefer [NewFAT] or [NewLittle], which supply them for you.
func NewFS[F FileHandle, D DirHandle[I], I fs.FileInfo](
	fsys FSNoAlloc[F, D, I],
	newFile func() F,
	newDir func() D,
	newInfo func() I,
) *FS[F, D, I] {
	fsys2 := &FS[F, D, I]{fs: fsys, newInfo: newInfo}
	fsys2.files.New = func() any { return &File[F]{h: newFile()} }
	fsys2.dirs.New = func() any { return &Dir[D, I]{h: newDir()} }
	return fsys2
}

// NewFAT wraps a mounted [FATFS] with handle pools.
func NewFAT(fsys *FATFS) *FS[*fat.File, *fat.Dir, *fat.FileInfo] {
	return NewFS(fsys,
		func() *fat.File { return new(fat.File) },
		func() *fat.Dir { return new(fat.Dir) },
		func() *fat.FileInfo { return new(fat.FileInfo) },
	)
}

// NewLittle wraps a mounted [LittleFS] with handle pools.
func NewLittle(fsys *LittleFS) *FS[*lfs.File, *lfs.Dir, *lfs.FileInfo] {
	return NewFS(fsys,
		func() *lfs.File { return new(lfs.File) },
		func() *lfs.Dir { return new(lfs.Dir) },
		func() *lfs.FileInfo { return new(lfs.FileInfo) },
	)
}

// Open opens path for reading.
func (fsys *FS[F, D, I]) Open(path string) (*File[F], error) {
	return fsys.OpenFile(path, os.O_RDONLY, 0)
}

// Create creates or truncates path and opens it for reading and writing.
func (fsys *FS[F, D, I]) Create(path string) (*File[F], error) {
	return fsys.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

// OpenFile opens path with the given os.O_* flags, mirroring [os.OpenFile]. The
// returned File must be closed; closing it is what returns its handle to the
// pool. See the backend's flag conversion method for what flag costs there.
func (fsys *FS[F, D, I]) OpenFile(path string, flag int, perm fs.FileMode) (*File[F], error) {
	f := fsys.files.Get().(*File[F])
	err := fsys.fs.OpenFile(f.h, path, flag, perm)
	if err != nil {
		// f.pool is still nil, so the handle was never handed out and is safe
		// to recycle immediately.
		fsys.files.Put(f)
		return nil, err
	}
	f.pool = &fsys.files
	return f, nil
}

// OpenDir opens path for iteration. The returned Dir must be closed.
func (fsys *FS[F, D, I]) OpenDir(path string) (*Dir[D, I], error) {
	d := fsys.dirs.Get().(*Dir[D, I])
	err := fsys.fs.OpenDir(d.h, path)
	if err != nil {
		fsys.dirs.Put(d)
		return nil, err
	}
	d.pool = &fsys.dirs
	return d, nil
}

// Stat returns information describing path. Unlike Open it allocates on every
// call: see the note on [FS].
func (fsys *FS[F, D, I]) Stat(path string) (I, error) {
	info := fsys.newInfo()
	err := fsys.fs.Stat(path, info)
	if err != nil {
		var zero I
		return zero, err
	}
	return info, nil
}

func (fsys *FS[F, D, I]) Mkdir(path string) error  { return fsys.fs.Mkdir(path) }
func (fsys *FS[F, D, I]) Remove(path string) error { return fsys.fs.Remove(path) }
func (fsys *FS[F, D, I]) Rename(oldpath, newpath string) error {
	return fsys.fs.Rename(oldpath, newpath)
}

var _ FileHandle = (*File[*fat.File])(nil)

// File is an open file handed out by [FS]. Close returns the underlying handle
// to the pool it came from and poisons this File, so that using it afterwards
// reports [fs.ErrClosed] instead of operating on a handle that a later Open may
// already have handed to someone else. That guard is the reason FS hands out a
// File rather than the backend handle itself.
type File[F FileHandle] struct {
	// pool is non-nil exactly while this File is open, and is the pool to
	// return h to on Close. It doubles as the open flag.
	pool *sync.Pool
	h    F
}

// Handle returns the underlying backend handle, for callers that need an
// operation this wrapper does not forward. It is only valid until Close.
func (f *File[F]) Handle() F { return f.h }

// Close closes the file and returns its handle to the pool. It is idempotent
// only in the sense that a second Close reports [fs.ErrClosed]; it never
// double-frees the handle to the pool.
func (f *File[F]) Close() error {
	if f.pool == nil {
		return errFileClosed
	}
	err := f.h.Close()
	pool := f.pool
	f.pool = nil // Poison before recycling: no later use can reach h.
	pool.Put(f)
	return err
}

func (f *File[F]) Read(buf []byte) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.Read(buf)
}

func (f *File[F]) ReadAt(p []byte, off int64) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.ReadAt(p, off)
}

func (f *File[F]) Write(buf []byte) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.Write(buf)
}

func (f *File[F]) WriteAt(p []byte, off int64) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.WriteAt(p, off)
}

func (f *File[F]) WriteString(s string) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.WriteString(s)
}

func (f *File[F]) Seek(offset int64, whence int) (int64, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.Seek(offset, whence)
}

func (f *File[F]) Truncate(size int64) error {
	if f.pool == nil {
		return errFileClosed
	}
	return f.h.Truncate(size)
}

func (f *File[F]) Sync() error {
	if f.pool == nil {
		return errFileClosed
	}
	return f.h.Sync()
}

// Dir is an open directory handed out by [FS], with the same close-and-recycle
// contract as [File].
type Dir[D DirHandle[I], I fs.FileInfo] struct {
	pool *sync.Pool
	h    D
}

// Handle returns the underlying backend handle. It is only valid until Close.
func (d *Dir[D, I]) Handle() D { return d.h }

// ForEachFile calls cb for every entry in the directory.
//
// The info passed to cb is owned by the backend and is reused across calls: both
// fat and lfs pass the same FileInfo every time. Retaining that pointer past the
// callback leaves you aliasing the next entry, so copy out whatever you need.
func (d *Dir[D, I]) ForEachFile(cb func(info I) error) error {
	if d.pool == nil {
		return errDirClosed
	}
	return d.h.ForEachFile(cb)
}

// Close closes the directory and returns its handle to the pool.
func (d *Dir[D, I]) Close() error {
	if d.pool == nil {
		return errDirClosed
	}
	err := d.h.Close()
	pool := d.pool
	d.pool = nil
	pool.Put(d)
	return err
}
