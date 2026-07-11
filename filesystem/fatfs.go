package filesystem

import (
	"io"
	"io/fs"
	"os"

	"github.com/soypat/fat"
)

// FATFS adapts a mounted [fat.FS] to [FSNoAlloc].
type FATFS struct {
	fs fat.FS
}

func (fs *FATFS) Mount(bd fat.BlockDevice, blockSize int, mode fat.Mode) error {
	return fs.fs.Mount(bd, blockSize, mode)
}

// mode converts portable os.O_* open flags into the [fat.Mode] to pass to
// [fat.FS.OpenFile], plus the fixups the caller must apply after the open for
// the flags FAT has no mode bit for. It is the authoritative description of what
// a portable open costs on FAT.
//
// Access bits map directly: O_RDONLY, O_WRONLY and O_RDWR become [fat.ModeRead],
// [fat.ModeWrite] and [fat.ModeRW]. Setting both O_WRONLY and O_RDWR is rejected.
//
// The creation disposition maps as:
//
//	O_CREATE|O_EXCL   fat.ModeCreateNew      fails if the file exists
//	O_CREATE|O_TRUNC  fat.ModeCreateAlways   creates, or truncates an existing file
//	O_CREATE          fat.ModeOpenAlways     creates, preserving an existing file
//	(none)            fat.ModeOpenExisting   fails if the file does not exist
//
// Two flags have no FAT equivalent and are emulated after the open:
//
//   - O_TRUNC without O_CREATE. FAT can only truncate as part of creating
//     (ModeCreateAlways), which would also create a missing file. postTrunc asks
//     the caller to open the existing file and Truncate(0) it instead, so a
//     missing file still fails.
//
//   - O_APPEND. [fat.ModeOpenAppend] looks like a match but is not: its value
//     includes the open-always bit, so it silently creates a missing file even
//     without O_CREATE. postSeekEnd instead asks the caller to seek to the end
//     after opening, which is what ModeOpenAppend does internally anyway, minus
//     the unwanted create. This method never returns ModeOpenAppend.
//
// Two divergences from [os.OpenFile] remain and cannot be fixed here:
//
//   - Append is not POSIX append. Both FAT and this emulation seek to the end
//     once, at open. They do not re-seek before every write, so a caller that
//     interleaves Seek and Write on an O_APPEND handle overwrites data where os
//     and littlefs would have appended it. littlefs is the one that gets this
//     right; see (*LittleFS).openFlags.
//
//   - perm is ignored. FAT stores only a read-only attribute and exports no
//     chmod, so permissions cannot be applied at create time. Read back,
//     fat.FileInfo.Mode synthesizes 0666, or 0444 when that attribute is set.
func (*FATFS) mode(flag int, perm fs.FileMode) (m fat.Mode, postTrunc, postSeekEnd bool, err error) {
	if flag&^supportedFlags != 0 {
		return 0, false, false, errUnsupportedFlag
	}
	read, write, err := access(flag)
	if err != nil {
		return 0, false, false, err
	}
	if read {
		m |= fat.ModeRead
	}
	if write {
		m |= fat.ModeWrite
	}
	create := flag&os.O_CREATE != 0
	excl := flag&os.O_EXCL != 0
	trunc := flag&os.O_TRUNC != 0
	if excl && !create {
		return 0, false, false, errExclNoCreate
	}
	switch {
	case create && excl:
		m |= fat.ModeCreateNew
	case create && trunc:
		m |= fat.ModeCreateAlways
	case create:
		m |= fat.ModeOpenAlways
	default:
		m |= fat.ModeOpenExisting
		postTrunc = trunc
	}
	return m, postTrunc, flag&os.O_APPEND != 0, nil
}

// OpenFile implements [FSNoAlloc], mirroring [os.OpenFile]. See (*FATFS).mode for how
// flag is translated and why perm is ignored.
func (fsys *FATFS) OpenFile(f *fat.File, path string, flag int, perm fs.FileMode) error {
	mode, postTrunc, postSeekEnd, err := fsys.mode(flag, perm)
	if err != nil {
		return err
	}
	err = fsys.fs.OpenFile(f, path, mode)
	if err != nil {
		return err
	}
	if postTrunc {
		err = f.Truncate(0)
	}
	if err == nil && postSeekEnd {
		_, err = f.Seek(0, io.SeekEnd)
	}
	if err != nil {
		f.Close() // Never leak an open handle out of a failed open.
		return err
	}
	return nil
}

func (fsys *FATFS) OpenDir(d *fat.Dir, path string) error   { return fsys.fs.OpenDir(d, path) }
func (fsys *FATFS) Mkdir(path string) error                 { return fsys.fs.Mkdir(path) }
func (fsys *FATFS) Remove(path string) error                { return fsys.fs.Remove(path) }
func (fsys *FATFS) Rename(oldpath, newpath string) error    { return fsys.fs.Rename(oldpath, newpath) }
func (fsys *FATFS) Stat(path string, i *fat.FileInfo) error { return fsys.fs.Stat(path, i) }
