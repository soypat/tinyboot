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
//     encodes. It is what you read back from a [FileInfo], not something you
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
//
// # Which interface to use
//
// [FSNoAlloc] is the allocation-free layer: it is generic over the backend's
// handle types and the caller owns every handle. [FS] is the convenient layer
// built on top of it. FS is deliberately not a generic type — the backend types
// are erased at construction, inside [NewFS] — so that the types a program
// passes around ([FS], [File], [Dir], [FileInfo]) never mention a type parameter
// and switching a program between FAT and littlefs changes no signature.
package filesystem

import (
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
)

// Wrapped so that a caller can detect use-after-close with the standard
// errors.Is(err, fs.ErrClosed), as they would with an *os.File.
var (
	errFileClosed = fmt.Errorf("filesystem: use of closed file: %w", fs.ErrClosed)
	errDirClosed  = fmt.Errorf("filesystem: use of closed directory: %w", fs.ErrClosed)
)

// FS is the convenient counterpart of [FSNoAlloc]: it owns the handle storage
// that FSNoAlloc makes the caller provide, so opens return a ready handle rather
// than filling one in. Handles come from a [sync.Pool] and are returned to it on
// Close, so a program that closes what it opens holds at most its peak number of
// concurrently open files and directories, and an open in steady state allocates
// nothing.
//
// "Steady state" is worth being precise about, because the two toolchains differ
// and only one of them gives a hard bound:
//
//   - On TinyGo the pool is a plain free list. Nothing ever empties it, so after
//     the peak is reached the handles are allocated once and reused forever. This
//     is the case the package is designed for.
//
//   - On standard Go the garbage collector drains a [sync.Pool]. An open that
//     lands after a collection therefore has to allocate its handle again. The
//     amortized cost is negligible — one handle per pooled object per GC cycle,
//     not one per open, as BenchmarkOpenClose shows — but it is not zero, and a
//     benchmark that reports a small nonzero B/op with 0 allocs/op is seeing
//     exactly this and not a leak.
//
// FS must not be copied after first use, as it contains a [sync.Pool].
//
// Stat is the one operation that must still allocate. A [FileInfo] has no Close,
// so nothing can ever hand it back, and there is no safe moment to recycle it.
// [Dir.ReadNext] allocates for that same reason; [Dir.ForEachFile] is the way to
// list a directory without allocating.
type FS struct {
	fs    ifs
	files sync.Pool // of *File, each with its backend handle already allocated.
	dirs  sync.Pool // of *Dir, likewise.
}

// NewFS wraps a mounted [FSNoAlloc] with handle pools, erasing its type
// parameters: the result is a plain *FS. The three constructors say how to
// allocate a backend handle when a pool is empty; they also let the compiler
// infer F, D and I, which it cannot do from fsys alone because those parameters
// appear only inside an interface.
//
// Prefer [NewFAT] or [NewLittle], which supply them for you.
func NewFS[F FileHandle, D DirHandle[I], I FileInfo](
	fsys FSNoAlloc[F, D, I],
	newFile func() F,
	newDir func() D,
	newInfo func() I,
) *FS {
	fsys2 := &FS{fs: &fsErased[F, D, I]{fs: fsys, newInfo: newInfo}}
	// F, D and I are all still in scope here, so the pools build their handles
	// directly. Routing this through ifs would only erase types that are not yet
	// erased, to recover them again on the next line.
	fsys2.files.New = func() any { return &File{h: newFile()} }
	fsys2.dirs.New = func() any { return &Dir{h: newDirErased(newInfo, newDir())} }
	return fsys2
}

// NewFAT wraps a mounted [FATFS] with handle pools.
func NewFAT(fsys *FATFS) *FS {
	return NewFS(fsys,
		func() *fat.File { return new(fat.File) },
		func() *fat.Dir { return new(fat.Dir) },
		func() *fat.FileInfo { return new(fat.FileInfo) },
	)
}

// NewLittle wraps a mounted [LittleFS] with handle pools.
func NewLittle(fsys *LittleFS) *FS {
	return NewFS(fsys,
		func() *lfs.File { return new(lfs.File) },
		func() *lfs.Dir { return new(lfs.Dir) },
		func() *lfs.FileInfo { return new(lfs.FileInfo) },
	)
}

// ifs is [FSNoAlloc] with its type parameters erased: handles cross this
// boundary as interfaces. It is what lets [FS] be a non-generic type. Its only
// implementation is [fsErased], which asserts each handle back to the backend's
// concrete type. Those assertions cannot fail: every handle FS passes down came
// out of the very fsErased that asserts it.
// Only info is a constructor: it is the one handle FS has to conjure from a
// method of its own ([FS.Stat]), where I is long gone. The file and directory
// handles are built in NewFS instead, which still has the type parameters.
type ifs interface {
	info() FileInfo
	openFile(f FileHandle, path string, flag int, perm fs.FileMode) error
	openDir(d idir, path string) error
	stat(path string, info FileInfo) error
	mkdir(path string) error
	remove(path string) error
	rename(oldpath, newpath string) error
}

type fsErased[F FileHandle, D DirHandle[I], I FileInfo] struct {
	fs      FSNoAlloc[F, D, I]
	newInfo func() I
}

func (e *fsErased[F, D, I]) info() FileInfo { return e.newInfo() }

func (e *fsErased[F, D, I]) openFile(f FileHandle, path string, flag int, perm fs.FileMode) error {
	return e.fs.OpenFile(f.(F), path, flag, perm)
}

func (e *fsErased[F, D, I]) openDir(d idir, path string) error {
	return e.fs.OpenDir(d.(*dirErased[I]).h.(D), path)
}

func (e *fsErased[F, D, I]) stat(path string, info FileInfo) error {
	return e.fs.Stat(path, info.(I))
}

func (e *fsErased[F, D, I]) mkdir(path string) error  { return e.fs.Mkdir(path) }
func (e *fsErased[F, D, I]) remove(path string) error { return e.fs.Remove(path) }
func (e *fsErased[F, D, I]) rename(oldpath, newpath string) error {
	return e.fs.Rename(oldpath, newpath)
}

// idir is [DirHandle] with its info type erased, so that [Dir] can be
// non-generic for the same reason [FS] is.
type idir interface {
	ReadNext() (FileInfo, error)
	ForEachFile(cb func(FileInfo) error) error
	Rewind() error
	Close() error
}

type dirErased[I FileInfo] struct {
	newInfo func() I
	h       DirHandle[I]
	// cb is the caller's callback for the ForEachFile call in progress, and
	// trampoline is the long-lived adapter that forwards to it. Splitting them
	// this way is what keeps a listing allocation-free: trampoline is built once
	// per handle, and only the pointer to cb changes per call. cb is nil except
	// during a ForEachFile, which is also what makes a reentrant call — listing a
	// directory from inside its own callback — a nil dereference rather than a
	// silent corruption of the iteration.
	cb         func(FileInfo) error
	trampoline func(I) error
}

// newDirErased binds the trampoline once, at construction, rather than closing
// over cb inside ForEachFile: a closure built per call would allocate on every
// listing and hand back the allocation ForEachFile exists to avoid.
func newDirErased[I FileInfo](newInfo func() I, h DirHandle[I]) *dirErased[I] {
	de := &dirErased[I]{newInfo: newInfo, h: h}
	de.trampoline = func(i I) error { return de.cb(i) }
	return de
}

// ReadNext allocates the info it returns: the caller keeps it, so it can never
// be recycled. Use ForEachFile to list a directory without allocating.
func (de *dirErased[I]) ReadNext() (FileInfo, error) {
	info := de.newInfo()
	err := de.h.ReadNext(info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// ForEachFile forwards the backend's own callback iteration, which reuses one
// info for the whole listing and so allocates nothing.
func (de *dirErased[I]) ForEachFile(cb func(FileInfo) error) error {
	de.cb = cb
	err := de.h.ForEachFile(de.trampoline)
	de.cb = nil
	return err
}

func (de *dirErased[I]) Close() error  { return de.h.Close() }
func (de *dirErased[I]) Rewind() error { return de.h.Rewind() }

// Open opens path for reading.
func (fsys *FS) Open(path string) (*File, error) {
	return fsys.OpenFile(path, os.O_RDONLY, 0)
}

// Create creates or truncates path and opens it for reading and writing.
func (fsys *FS) Create(path string) (*File, error) {
	return fsys.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

// OpenFile opens path with the given os.O_* flags, mirroring [os.OpenFile]. The
// returned File must be closed; closing it is what returns its handle to the
// pool. See the backend's flag conversion method for what flag costs there.
func (fsys *FS) OpenFile(path string, flag int, perm fs.FileMode) (*File, error) {
	f := fsys.files.Get().(*File)
	err := fsys.fs.openFile(f.h, path, flag, perm)
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
func (fsys *FS) OpenDir(path string) (*Dir, error) {
	d := fsys.dirs.Get().(*Dir)
	err := fsys.fs.openDir(d.h, path)
	if err != nil {
		fsys.dirs.Put(d)
		return nil, err
	}
	d.pool = &fsys.dirs
	return d, nil
}

// Stat returns information describing path. Unlike Open it allocates on every
// call: see the note on [FS].
func (fsys *FS) Stat(path string) (FileInfo, error) {
	info := fsys.fs.info()
	err := fsys.fs.stat(path, info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (fsys *FS) Mkdir(path string) error  { return fsys.fs.mkdir(path) }
func (fsys *FS) Remove(path string) error { return fsys.fs.remove(path) }
func (fsys *FS) Rename(oldpath, newpath string) error {
	return fsys.fs.rename(oldpath, newpath)
}

var _ FileHandle = (*File)(nil)

// File is an open file handed out by [FS]. Close returns the underlying handle
// to the pool it came from and poisons this File, so that using it afterwards
// reports [fs.ErrClosed] instead of operating on a handle that a later Open may
// already have handed to someone else. That guard is the reason FS hands out a
// File rather than the backend handle itself.
type File struct {
	// pool is non-nil exactly while this File is open, and is the pool to
	// return h to on Close. It doubles as the open flag.
	pool *sync.Pool
	h    FileHandle
}

// Close closes the file and returns its handle to the pool. It is idempotent
// only in the sense that a second Close reports [fs.ErrClosed]; it never
// double-frees the handle to the pool.
func (f *File) Close() error {
	if f.pool == nil {
		return errFileClosed
	}
	err := f.h.Close()
	pool := f.pool
	f.pool = nil // Poison before recycling: no later use can reach h.
	pool.Put(f)
	return err
}

func (f *File) Read(buf []byte) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.Read(buf)
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.ReadAt(p, off)
}

func (f *File) Write(buf []byte) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.Write(buf)
}

func (f *File) WriteAt(p []byte, off int64) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.WriteAt(p, off)
}

func (f *File) WriteString(s string) (int, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.WriteString(s)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	if f.pool == nil {
		return 0, errFileClosed
	}
	return f.h.Seek(offset, whence)
}

func (f *File) Truncate(size int64) error {
	if f.pool == nil {
		return errFileClosed
	}
	return f.h.Truncate(size)
}

func (f *File) Sync() error {
	if f.pool == nil {
		return errFileClosed
	}
	return f.h.Sync()
}

// Dir is an open directory handed out by [FS], with the same close-and-recycle
// contract as [File]: once closed, every method reports [fs.ErrClosed] rather
// than reaching a handle the pool may already have handed to a later open.
type Dir struct {
	pool *sync.Pool
	h    idir
}

// ReadNext returns the next entry in the directory. It allocates the info it
// returns; ForEachFile does not.
func (d *Dir) ReadNext() (FileInfo, error) {
	if d.pool == nil {
		return nil, errDirClosed
	}
	return d.h.ReadNext()
}

// ForEachFile calls cb once per entry without allocating. cb is lent a single
// info that is overwritten before the next call, so cb must copy out what it
// needs (see [FileInfo.AppendName]) rather than retain it.
func (d *Dir) ForEachFile(cb func(FileInfo) error) error {
	if d.pool == nil {
		return errDirClosed
	}
	return d.h.ForEachFile(cb)
}

func (d *Dir) Rewind() error {
	if d.pool == nil {
		return errDirClosed
	}
	return d.h.Rewind()
}

// Close closes the directory and returns its handle to the pool.
func (d *Dir) Close() error {
	if d.pool == nil {
		return errDirClosed
	}
	err := d.h.Close()
	pool := d.pool
	d.pool = nil
	pool.Put(d)
	return err
}
