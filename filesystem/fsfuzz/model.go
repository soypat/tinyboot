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

	// AppendPerWrite is true POSIX append: seek to the end before every write, and
	// leave the offset alone the rest of the time. littlefs does this natively.
	//
	// FAT has no native append that this package can use, so (*FATFS).OpenFile
	// emulates one by seeking to the end ONCE, at open. That gets a plain
	// open-and-append right and everything else wrong:
	//
	//   - A Seek on an O_APPEND handle sticks, so the next write lands wherever
	//     the caller seeked instead of at the end.
	//   - The open-time seek moves the READ offset too. A handle opened
	//     O_RDONLY|O_APPEND starts at the end of the file and reads EOF, where os
	//     and littlefs start it at zero and hand back the file. POSIX is explicit
	//     that O_APPEND governs writes only.
	//
	// The second one is a bug, found by the fuzzer and pinned by
	// TestDivergenceAppendMovesReadOffset. It is modeled rather than quarantined
	// because this flag already had to exist to describe the first one.
	AppendPerWrite bool

	// AliasedOpen allows more than one live handle on the same path. littlefs
	// explicitly does not support it, so programs that try are skipped.
	AliasedOpen bool

	// RemoveOpen allows removing or renaming a file that has a live handle, as
	// POSIX does. Neither backend defines it.
	RemoveOpen bool

	// RenameOverwrite allows renaming onto an existing destination.
	RenameOverwrite bool

	// The four fields below are QUARANTINE FLAGS, not capabilities. Each one
	// names a bug this fuzzer found, and each is set on exactly the backend that
	// gets the behavior wrong; the other backend, and os.File, do the right
	// thing. They are here so the fuzzer stops re-reporting known findings on
	// every other program and gets on with looking for the next one.
	//
	// Every one of them is pinned by a test in divergence_test.go that asserts
	// the CURRENT, WRONG behavior. Fix the underlying bug and that test fails,
	// which is the signal to delete the flag and the test together. A quarantine
	// flag that outlives its bug is how a fuzzer goes quietly blind.

	// ReadIgnoresAccessMode: Read and ReadAt return data through a handle opened
	// os.O_WRONLY instead of refusing. littlefs only. See divergence_test.go.
	ReadIgnoresAccessMode bool

	// SeekBoundedBySize: the file position is not allowed to exceed the file
	// size. FatFs f_lseek enforces this in two incompatible ways depending on how
	// the file was opened — on a writable handle it EXTENDS the file out to the
	// requested offset, and on a read-only handle it CLIPS the seek back to the
	// end and reports the clipped offset as if it had succeeded. os and littlefs
	// do neither: the position goes where it was asked to go, and the hole
	// appears only when something writes into it. FAT only.
	SeekBoundedBySize bool

	// TruncateMovesOffset: Truncate clamps the file offset to the new size
	// instead of leaving it where the caller put it. FAT only.
	TruncateMovesOffset bool

	// HolesAreGarbage: a region a file grows over without anything writing to it
	// reads back as whatever was on the media, rather than as zeros. FAT only,
	// and the most serious of these: FatFs allocates the clusters and does not
	// erase them, so a read through the hole returns the raw contents of the
	// device. On the RAM device here that is the 0xff of erased flash, which is
	// harmless; on a real part it is whatever those blocks last held, which may
	// be the contents of a deleted file. os and littlefs both zero-fill.
	HolesAreGarbage bool
}

// CapsFAT and CapsLittle describe the backends this repository ships.
//
// CapsFAT covers both FAT32 and exFAT: they are one driver above the FAT itself,
// and the fuzzer confirms every bug below reproduces identically on both. Long
// file names cap at 255 on either.
var (
	CapsFAT = Caps{
		MaxNameLen:      255,
		CaseInsensitive: true,
		AppendPerWrite:  false, // Seeks to end once, at open. See the field: it is a bug.

		SeekBoundedBySize:   true, // BUG, quarantined. See Caps and divergence_test.go.
		TruncateMovesOffset: true, // BUG, quarantined.
		HolesAreGarbage:     true, // BUG, quarantined.
	}
	CapsLittle = Caps{
		MaxNameLen:     255,
		AppendPerWrite: true, // Real POSIX append.

		ReadIgnoresAccessMode: true, // BUG, quarantined.
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

	// tainted marks a file that has grown over a hole on a backend where holes
	// read back as garbage (see Caps.HolesAreGarbage). The model cannot say what
	// those bytes are — that is the whole complaint — so the content oracle stops
	// checking this file's bytes for the rest of the run. Everything structural
	// still applies: its size, the errors it reports, where EOF is.
	//
	// It is per file and sticky rather than a per-byte map of which bytes are
	// known. A bitmap would recover byte checking on the parts of a tainted file
	// that were later written, at the cost of carrying a bit per byte of every
	// file in the model. The taint is rare, so the coarse version is the right
	// trade.
	tainted bool

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
		m.nodes[i].tainted = false
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
// must report, and — when it must succeed — the file offset the handle starts at.
func (m *model) wantOpen(p string, flag int) (want class, off int64) {
	if flag&^supportedFlags != 0 {
		return classOther, 0 // errUnsupportedFlag: not mapped to a sentinel.
	}
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY, os.O_WRONLY, os.O_RDWR:
	default:
		return classOther, 0 // errBadAccessMode.
	}
	create, excl, trunc := flag&os.O_CREATE != 0, flag&os.O_EXCL != 0, flag&os.O_TRUNC != 0
	if excl && !create {
		return classOther, 0 // errExclNoCreate.
	}
	if m.nameTooLong(p) {
		return classOther, 0
	}

	n := m.node(p)
	switch {
	case n != nil && n.exists && n.dir:
		return classOther, 0 // Opening a directory as a file.
	case n != nil && n.exists && create && excl:
		return classExist, 0
	case (n == nil || !n.exists) && !create:
		return classNotExist, 0
	case n == nil || !n.exists:
		// Creating it. The parent has to be there, and has to be a directory.
		if !m.parentExists(p) {
			return classNotExist, 0
		}
		if !m.parentOK(p) {
			return classOther, 0 // The parent is a regular file.
		}
	}

	// The open succeeds. Work out the resulting size and offset.
	size := int64(0)
	if n.exists && !trunc {
		size = int64(len(n.data))
	}
	if flag&os.O_APPEND != 0 && !m.caps.AppendPerWrite {
		// FAT has no native append, so (*FATFS).OpenFile emulates it by seeking to
		// the end once, at open — which moves the READ offset too, and POSIX says
		// O_APPEND must not. A handle opened O_RDONLY|O_APPEND starts at the end of
		// the file and reads EOF. os and littlefs both start it at zero and only
		// move to the end when something writes. See Caps.AppendPerWrite and
		// TestDivergenceAppendMovesReadOffset.
		off = size
	}
	return classOK, off
}

// applyOpen commits a successful open to the model.
func (m *model) applyOpen(slot int, p string, flag int, off int64) {
	n := m.node(p)
	n.exists, n.dir = true, false
	if flag&os.O_TRUNC != 0 {
		n.data = n.data[:0]
		n.tainted = false // Nothing is left in it to be unknown.
	}
	m.files[slot] = mfile{state: hsOpen, path: p, off: off, flag: flag}
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
