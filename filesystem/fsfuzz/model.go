package fsfuzz

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// class is a coarse classification of an error, and the thing the oracle
// actually compares. Comparing error identity across two unrelated filesystems
// would be comparing their C ancestries, not their semantics.
//
// The split between the strict classes and classOther is not cosmetic — it is
// what keeps this fuzzer's false positive rate at zero, and it is dictated by
// what the backends actually promise. fat.fileResult.Is and lfs.lfsError.Is map
// only ErrNotExist, ErrExist and ErrInvalid (FAT adds ErrPermission) onto
// standard sentinels. Nothing maps no-space, not-a-directory, is-a-directory or
// directory-not-empty. So those cannot be told apart from each other, and an
// oracle that pretended otherwise would fail on correct code.
//
// FAT's ErrPermission deserves special mention: FatFs returns FR_DENIED both for
// a genuine refusal and for a full disk, so ErrPermission carries no reliable
// meaning here and is deliberately NOT a strict class.
type class uint8

const (
	classOK       class = iota // No error.
	classNotExist              // fs.ErrNotExist.
	classExist                 // fs.ErrExist.
	classInvalid               // fs.ErrInvalid.
	classClosed                // fs.ErrClosed — this package's own guard, always exact.
	classEOF                   // io.EOF.
	classOther                 // Anything else: unmapped, unclassifiable, or no-space.
)

var className = [...]string{
	classOK: "success", classNotExist: "ErrNotExist", classExist: "ErrExist",
	classInvalid: "ErrInvalid", classClosed: "ErrClosed", classEOF: "io.EOF",
	classOther: "unclassified error",
}

func (c class) String() string { return className[c] }

// strict reports whether a class is precise enough to compare. The others are
// wildcards: an expectation of classOther means "this must fail, but the way it
// fails is not something either backend defines".
func (c class) strict() bool {
	return c == classOK || c == classNotExist || c == classExist || c == classClosed || c == classEOF
}

func classify(err error) class {
	switch {
	case err == nil:
		return classOK
	case errors.Is(err, io.EOF):
		return classEOF
	case errors.Is(err, fs.ErrClosed):
		return classClosed
	case errors.Is(err, fs.ErrNotExist):
		return classNotExist
	case errors.Is(err, fs.ErrExist):
		return classExist
	case errors.Is(err, fs.ErrInvalid):
		return classInvalid
	}
	return classOther
}

// Caps describes where a backend's behavior is its own. Two kinds of divergence
// live here and they are handled very differently:
//
//   - Divergences the backend defines, such as littlefs seeking to the end
//     before every append write where FAT seeks once at open. The model
//     reproduces these, so the operation still runs and is still checked.
//
//   - Behavior neither backend defines, such as two live handles on one file.
//     The model cannot have an opinion, so the executor skips the operation
//     outright. Crucially, the skip is decided from model state, not from the
//     input, so it consumes no entropy and one corpus runs against backends with
//     different capabilities.
type Caps struct {
	// MaxNameLen is the longest path element the backend accepts.
	MaxNameLen int

	// CaseInsensitive folds names, as FAT does and littlefs does not.
	CaseInsensitive bool

	// AppendForwardOnly: O_APPEND drags the file position forward to the end of
	// the file before a write, but never drags it BACK. A handle deliberately
	// seeked PAST the end writes where it was left, sparsely, instead of at the
	// end.
	//
	// littlefs only, and it is not a port bug: lfs_file_write guards the move with
	// (file->pos < file->ctz.size), and the Go library copies the C library
	// faithfully. POSIX says a write on an O_APPEND handle always goes to the end,
	// so this is upstream littlefs departing from POSIX, and fixing it here would
	// mean diverging from the reference for a case you have to go out of your way
	// to reach. Modeled instead. See TestAppendMovesOnlyBackwards.
	//
	// FAT does not set this: fat.ModeAppend is the POSIX append — every write
	// goes to the end, wherever the position was.
	AppendForwardOnly bool

	// AliasedOpen allows more than one live handle on the same path. littlefs
	// explicitly does not support it, so programs that try are skipped.
	AliasedOpen bool

	// RemoveOpen allows removing or renaming a file that has a live handle, as
	// POSIX does. Neither backend defines it.
	RemoveOpen bool

	// RenameOverwrite allows renaming onto an existing destination.
	RenameOverwrite bool
}

// CapsFAT and CapsLittle describe the backends this repository ships.
//
// CapsFAT covers both FAT32 and exFAT: they are one driver above the FAT itself,
// and every divergence the fuzzer has found reproduced identically on both. Long
// file names cap at 255 on either.
//
// There are no quarantine flags left. There used to be four, each naming a bug
// this fuzzer found and each telling the model to expect the wrong answer so the
// fuzzer would stop re-reporting it and go looking for the next one:
//
//	ReadIgnoresAccessMode  littlefs returned data through an O_WRONLY handle
//	SeekBoundedBySize      FAT grew the file on a seek past EOF, and clipped a read-only one
//	TruncateMovesOffset    FAT clamped the file offset to the new size
//	HolesAreGarbage        FAT handed back the raw media where a file had grown over it
//
// All four are fixed upstream, in soypat/lfs and soypat/fat, so the model now
// asserts the correct behavior on every one of them and the fuzzer enforces it.
// That is what a quarantine is for: it is scaffolding, and it comes down.
var (
	CapsFAT = Caps{
		MaxNameLen:      255,
		CaseInsensitive: true,
	}
	CapsLittle = Caps{
		MaxNameLen:        255,
		AppendForwardOnly: true, // Upstream littlefs, faithfully ported. See the field.
	}
)

// pathIndex maps a path back to its slot in [Paths]. Built once, read-only,
// never written: a per-run map would be an allocation per fuzz iteration, and
// there are a great many fuzz iterations.
var pathIndex = func() map[string]int {
	m := make(map[string]int, len(Paths))
	for i, p := range Paths {
		m[p] = i
	}
	return m
}()

// handleState distinguishes a slot that was never opened from one that was
// opened and then closed. They behave differently and the difference is the
// point: a closed slot keeps its [filesystem.File], so the next operation on it
// drives the poison guard in fs_alloc.go and must report fs.ErrClosed.
type handleState uint8

const (
	hsFree handleState = iota
	hsOpen
	hsClosed
)

type mnode struct {
	exists bool
	dir    bool

	// data is retained across runs, deliberately. Zeroing its length rather than
	// dropping the slice means a fuzz iteration reuses the backing array the last
	// one grew, so after a short warmup the model stops allocating file contents
	// entirely. Since the contents are bounded by the size of the device, so is
	// the memory this holds.
	data []byte
}

type mfile struct {
	state handleState
	path  string
	off   int64
	flag  int
}

type mdir struct {
	state handleState
	path  string
	// seen names returned by ReadNext since the last open or rewind. Directory
	// iteration order is the backend's business, so the oracle checks membership
	// and absence of duplicates rather than a sequence.
	seen map[string]bool
}

// model is the reference filesystem: the thing the implementation under test is
// compared against. It is deliberately dumb. Every subtlety it does have is
// forced on it by a documented backend behavior, because a clever model is a
// model with its own bugs, and a fuzzer cannot tell you which of the two sides
// is wrong.
//
// Its namespace is [Paths] and nothing else, so it is an array rather than a
// map: a program cannot name a file outside the alphabet, the alphabet is closed
// under parent (every path's parent is also in it), and an array of sixteen
// nodes whose buffers survive a reset costs one allocation for the life of the
// process rather than one per fuzz iteration.
type model struct {
	caps  Caps
	nodes [len(Paths)]mnode
	files [NumFiles]mfile
	dirs  [NumDirs]mdir

	children []string // Listing scratch, reused.
}

// reset returns the model to a bare root filesystem, keeping every buffer it has
// already grown.
func (m *model) reset(caps Caps) {
	m.caps = caps
	for i := range m.nodes {
		m.nodes[i].exists = false
		m.nodes[i].dir = false
		m.nodes[i].data = m.nodes[i].data[:0] // Keep the backing array.
	}
	m.files = [NumFiles]mfile{}
	for i := range m.dirs {
		seen := m.dirs[i].seen
		if seen == nil {
			seen = make(map[string]bool, 16)
		} else {
			clear(seen)
		}
		m.dirs[i] = mdir{seen: seen}
	}
	m.children = m.children[:0]

	root := m.node("/")
	root.exists, root.dir = true, true
}

// key normalizes a path, folding case when the backend does. The alphabet is
// already clean and lowercase, so both path.Clean and strings.ToLower hit their
// no-change fast paths and return the input without allocating. The fold still
// matters: on FAT, "/A" and "/a" are the same file, and a model that disagreed
// would report a bug in every program that touched both.
func (m *model) key(p string) string {
	p = path.Clean(p)
	if m.caps.CaseInsensitive {
		p = strings.ToLower(p)
	}
	return p
}

// node returns the node for p, or nil when p is not a name the model can hold.
// Only a name the implementation invented — an entry in a directory listing that
// should not be there — can miss, and that is a finding, not an error.
func (m *model) node(p string) *mnode {
	i, ok := pathIndex[m.key(p)]
	if !ok {
		return nil
	}
	return &m.nodes[i]
}

// exists reports whether p is a live file or directory.
func (m *model) exists(p string) bool {
	n := m.node(p)
	return n != nil && n.exists
}

// nameTooLong reports whether any element of p exceeds the backend's limit.
func (m *model) nameTooLong(p string) bool {
	for _, elem := range strings.Split(p, "/") {
		if len(elem) > m.caps.MaxNameLen {
			return true
		}
	}
	return false
}

// parentExists reports whether p's parent is a live node of any kind, and
// parentOK whether it is a live directory. A path whose parent is a regular file
// — "/a/x" where "/a" is a file — must fail, but with a class neither backend
// maps to a sentinel, so the two are distinguished here and not conflated.
func (m *model) parentExists(p string) bool { return m.exists(path.Dir(m.key(p))) }

func (m *model) parentOK(p string) bool {
	parent := m.node(path.Dir(m.key(p)))
	return parent != nil && parent.exists && parent.dir
}

// childrenOf returns the sorted names directly under dir, in a buffer that is
// reused between calls. The caller must not hold onto it across another call.
func (m *model) childrenOf(dir string) []string {
	key := m.key(dir)
	m.children = m.children[:0]
	for i := range m.nodes {
		if !m.nodes[i].exists || Paths[i] == "/" || path.Dir(Paths[i]) != key {
			continue
		}
		m.children = append(m.children, path.Base(Paths[i]))
	}
	sort.Strings(m.children)
	return m.children
}

// openHandles counts live handles on p, which is what decides whether an
// operation is aliasing and must therefore be skipped on a backend that does not
// define aliasing.
func (m *model) openHandles(p string) int {
	key, n := m.key(p), 0
	for i := range m.files {
		if m.files[i].state == hsOpen && m.key(m.files[i].path) == key {
			n++
		}
	}
	for i := range m.dirs {
		if m.dirs[i].state == hsOpen && m.key(m.dirs[i].path) == key {
			n++
		}
	}
	return n
}

// supportedFlags mirrors the constant of the same name in the filesystem
// package, which is unexported. Duplicated rather than exported, because
// exporting it would put a fuzzing detail into the package's public API.
const supportedFlags = os.O_RDONLY | os.O_WRONLY | os.O_RDWR |
	os.O_CREATE | os.O_EXCL | os.O_TRUNC | os.O_APPEND

// wantOpen is the model's verdict on an OpenFile: the class the implementation
// must report.
//
// It says nothing about the resulting file offset because there is nothing to
// say: a fresh handle starts at zero. It used to return an offset, because FAT
// emulated O_APPEND by seeking to the end at open, which moved the offset a Read
// would start from. POSIX says O_APPEND governs writes only, and it now does.
func (m *model) wantOpen(p string, flag int) (want class) {
	if flag&^supportedFlags != 0 {
		return classOther // errUnsupportedFlag: not mapped to a sentinel.
	}
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY, os.O_WRONLY, os.O_RDWR:
	default:
		return classOther // errBadAccessMode.
	}
	create, excl := flag&os.O_CREATE != 0, flag&os.O_EXCL != 0
	if excl && !create {
		return classOther // errExclNoCreate.
	}
	if m.nameTooLong(p) {
		return classOther
	}

	n := m.node(p)
	switch {
	case n != nil && n.exists && n.dir:
		return classOther // Opening a directory as a file.
	case n != nil && n.exists && create && excl:
		return classExist
	case (n == nil || !n.exists) && !create:
		return classNotExist
	case n == nil || !n.exists:
		// Creating it. The parent has to be there, and has to be a directory.
		if !m.parentExists(p) {
			return classNotExist
		}
		if !m.parentOK(p) {
			return classOther // The parent is a regular file.
		}
	}
	return classOK
}

// applyOpen commits a successful open to the model.
func (m *model) applyOpen(slot int, p string, flag int) {
	n := m.node(p)
	n.exists, n.dir = true, false
	if flag&os.O_TRUNC != 0 {
		n.data = n.data[:0]
	}
	m.files[slot] = mfile{state: hsOpen, path: p, off: 0, flag: flag}
}

func (f *mfile) readable() bool {
	return f.flag&(os.O_RDONLY|os.O_WRONLY|os.O_RDWR) != os.O_WRONLY
}

func (f *mfile) writable() bool {
	return f.flag&(os.O_WRONLY|os.O_RDWR) != 0
}

// writeAt applies a write of buf at off, zero-filling any gap. Both backends
// zero-fill a sparse write rather than leaving the gap undefined.
//
// It grows the file and never shrinks it: a write that ends before the current
// end of the file overwrites the middle of it and leaves the tail alone. Routing
// this straight through resize would instead truncate the file to the end of
// every write, which is the model quietly corrupting itself.
func (n *mnode) writeAt(buf []byte, off int64) {
	if end := off + int64(len(buf)); end > int64(len(n.data)) {
		n.resize(end)
	}
	copy(n.data[off:], buf)
}

func (n *mnode) truncate(size int64) { n.resize(size) }

// resize grows or shrinks the node to size, zeroing anything newly exposed and
// keeping the backing array whenever it is already big enough. Reusing the array
// is what keeps a fuzz iteration from allocating the whole contents of the
// filesystem all over again.
func (n *mnode) resize(size int64) {
	switch {
	case size <= int64(cap(n.data)):
		old := len(n.data)
		n.data = n.data[:size]
		if int(size) > old {
			clear(n.data[old:])
		}
	default:
		grown := make([]byte, size)
		copy(grown, n.data)
		n.data = grown
	}
}
