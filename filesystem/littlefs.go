package filesystem

import (
	"io/fs"
	"os"

	"github.com/soypat/lfs"
)

// LittleFS adapts a mounted [lfs.FS] to [FSNoAlloc].
type LittleFS struct {
	fs lfs.FS
}

func (fsys *LittleFS) Mount(bd lfs.BlockDevice, pageSize int, blockSize int, mode lfs.Mode) error {
	return fsys.fs.Mount(bd, pageSize, blockSize, mode)
}

// openFlags converts portable os.O_* open flags into the [lfs.OpenFlags] to pass
// to [lfs.FS.OpenFile]. littlefs was modelled on the POSIX flags, so unlike FAT
// the mapping is one-to-one and needs no post-open fixups:
//
//	O_RDONLY  lfs.ReadOnly     O_CREATE  lfs.Create
//	O_WRONLY  lfs.WriteOnly    O_EXCL    lfs.Excl
//	O_RDWR    lfs.ReadWrite    O_TRUNC   lfs.Truncate
//	                           O_APPEND  lfs.Append
//
// [lfs.Append] is true POSIX append: it seeks to the end before every write. This
// is a real behavioral difference from FAT, not merely a difference in spelling —
// see (*FATFS).mode, whose append seeks to the end only once, at open.
//
// O_EXCL without O_CREATE is rejected. littlefs would accept it and report an
// already-exists error for a file the caller never asked to create, which is not
// what [os.OpenFile] does.
//
// perm is ignored: littlefs stores no metadata at all, neither permissions nor
// timestamps. lfs.FileInfo.Mode is a synthetic constant and lfs.FileInfo.ModTime
// is always the zero time.
func (*LittleFS) openFlags(flag int, perm fs.FileMode) (of lfs.OpenFlags, err error) {
	if flag&^supportedFlags != 0 {
		return 0, errUnsupportedFlag
	}
	read, write, err := access(flag)
	if err != nil {
		return 0, err
	}
	switch {
	case read && write:
		of = lfs.ReadWrite
	case write:
		of = lfs.WriteOnly
	default:
		of = lfs.ReadOnly
	}
	create := flag&os.O_CREATE != 0
	excl := flag&os.O_EXCL != 0
	if excl && !create {
		return 0, errExclNoCreate
	}
	if create {
		of |= lfs.Create
	}
	if excl {
		of |= lfs.Excl
	}
	if flag&os.O_TRUNC != 0 {
		of |= lfs.Truncate
	}
	if flag&os.O_APPEND != 0 {
		of |= lfs.Append
	}
	return of, nil
}

// OpenFile implements [FSNoAlloc], mirroring [os.OpenFile]. See (*LittleFS).openFlags
// for how flag is translated and why perm is ignored.
func (fsys *LittleFS) OpenFile(f *lfs.File, path string, flag int, perm fs.FileMode) error {
	of, err := fsys.openFlags(flag, perm)
	if err != nil {
		return err
	}
	return fsys.fs.OpenFile(f, path, of)
}

func (fsys *LittleFS) OpenDir(d *lfs.Dir, path string) error   { return fsys.fs.OpenDir(d, path) }
func (fsys *LittleFS) Mkdir(path string) error                 { return fsys.fs.Mkdir(path) }
func (fsys *LittleFS) Remove(path string) error                { return fsys.fs.Remove(path) }
func (fsys *LittleFS) Rename(oldpath, newpath string) error    { return fsys.fs.Rename(oldpath, newpath) }
func (fsys *LittleFS) Stat(path string, i *lfs.FileInfo) error { return fsys.fs.Stat(path, i) }
