package fsfuzz

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sort"

	"github.com/soypat/tinyboot/filesystem"
)

// The runner executes a [Program] against a real filesystem, checking every
// operation against a reference model. A panic in the implementation is not
// caught: the fuzzing engine wants it, and a panic is a finding in its own right.
//
// Running is deterministic and consumes no entropy. Every decision made here —
// which operations to skip, what to expect, when to stop — is a function of the
// program and of the model state that program produced. That is what lets a
// check be added below without invalidating a single corpus file.
//
// A runner is owned by a [Harness] and reused across runs. Its buffers are sized
// once, at [MaxIO], and never grow: a fuzz iteration allocates nothing here.
type runner struct {
	fsys *filesystem.FS
	caps Caps
	m    model
	prog Program

	files [NumFiles]*filesystem.File
	dirs  [NumDirs]*filesystem.Dir

	// dirty marks that the tree changed while directory handles were open.
	// Iterating a directory across a mutation is undefined on both backends, so
	// a dirty handle accepts nothing but Close.
	dirty [NumDirs]bool

	buf   []byte   // Read scratch.
	wbuf  []byte   // Write scratch.
	names []string // Listing scratch.

	// poisoned stops the run without failing it. See poison.
	poisoned bool
	idx      int // Index of the operation being executed, for error messages.
}

// reset prepares the runner for another program, reusing every buffer it already
// has. The handle tables are cleared because the filesystem underneath has been
// reset and remounted, so the pointers in them address handles that no longer
// mean anything.
func (r *runner) reset(fsys *filesystem.FS, caps Caps, prog Program) *runner {
	r.fsys, r.caps, r.prog = fsys, caps, prog
	r.files = [NumFiles]*filesystem.File{}
	r.dirs = [NumDirs]*filesystem.Dir{}
	r.dirty = [NumDirs]bool{}
	r.poisoned, r.idx = false, 0
	if r.buf == nil {
		r.buf = make([]byte, MaxIO)
		r.wbuf = make([]byte, MaxIO)
		r.names = make([]string, 0, 32)
	}
	r.m.reset(caps)
	return r
}

func (r *runner) run() error {
	defer r.closeAll()
	for i, op := range r.prog {
		r.idx = i
		err := r.step(op)
		if err != nil {
			return err
		}
		if r.poisoned {
			return nil
		}
	}
	return nil
}

// closeAll returns every still-open handle to the pool. It is deferred, so it
// also runs when a program fails or panics.
//
// This is not tidiness, it is the memory discipline the whole harness depends
// on. A [filesystem.File] goes back to its pool in Close and nowhere else, so a
// handle that is merely dropped is a handle the pool has lost: the next open
// allocates a fresh one, and a fuzzer doing that a hundred thousand times a
// second is allocating a backend handle per open forever. A fuzz program has no
// reason to close what it opened, so the harness closes it for them.
//
// [runner.leaked] turns "I believe this is complete" into something the tests
// check.
func (r *runner) closeAll() {
	for i, f := range r.files {
		if f != nil && r.m.files[i].state == hsOpen {
			f.Close()
			r.m.files[i].state = hsClosed
		}
	}
	for i, d := range r.dirs {
		if d != nil && r.m.dirs[i].state == hsOpen {
			d.Close()
			r.m.dirs[i].state = hsClosed
		}
	}
}

// leaked reports how many handles the run failed to return to the pool. It must
// be zero after any run: see closeAll. Exposed to the tests through
// [Harness.Leaked].
func (r *runner) leaked() int {
	n := 0
	for i := range r.files {
		if r.m.files[i].state == hsOpen {
			n++
		}
	}
	for i := range r.dirs {
		if r.m.dirs[i].state == hsOpen {
			n++
		}
	}
	return n
}

// poison abandons the rest of the program without failing it. It is the release
// valve that keeps this fuzzer free of false positives.
//
// The two things it exists for are a full device and an unclassifiable error.
// Once the backend reports either, the model and the implementation may have
// legitimately diverged — a failed write may have written some of its bytes, a
// failed create may have left a directory entry — and there is no way to
// reconcile them from the outside. Continuing would report a "bug" on every
// subsequent operation. Stopping loses the tail of one program, which the fuzzer
// will happily regenerate.
//
// Panics are unaffected: poisoning only silences the differential oracle, and a
// panic is not something the oracle has to notice.
func (r *runner) poison() { r.poisoned = true }

// fail reports a disagreement, quoting the operation and the program that
// produced it.
func (r *runner) fail(format string, args ...any) error {
	return fmt.Errorf("op %d (%s): %s\n\nprogram:\n%s",
		r.idx, r.prog[r.idx], fmt.Sprintf(format, args...), r.prog)
}

// check compares the class of the implementation's error against the model's
// expectation, and reports whether the operation succeeded so the caller knows
// whether to go on and check its results.
//
// The asymmetry here is deliberate and is the core of the oracle:
//
//   - The implementation succeeding where the model demanded failure is ALWAYS a
//     bug. A filesystem that creates a file under O_EXCL, or reads through a
//     closed handle, is broken no matter what the backends do or do not promise.
//     There is no escape hatch for this case.
//
//   - The implementation failing where the model expected success is a bug only
//     if the failure is one we can name. A spurious ErrNotExist is a bug. An
//     unnameable error might be a full device, so it poisons instead.
//
//   - Two named-but-different failures are a bug. Anything involving an unnamed
//     class is accepted, because neither backend maps not-a-directory,
//     is-a-directory, directory-not-empty or no-space onto a sentinel, and an
//     oracle that guessed at them would fail on correct code.
func (r *runner) check(want class, err error) (ok bool, failure error) {
	got := classify(err)
	switch {
	case got == want:
		return got == classOK, nil

	case want != classOK && got == classOK:
		return false, r.fail("succeeded, want %s", want)

	case want == classOK && got != classOK:
		if got.strict() {
			return false, r.fail("failed with %s (%v), want success", got, err)
		}
		r.poison() // Possibly a full device. Not something we can adjudicate.
		return false, nil

	case want.strict() && got.strict():
		return false, r.fail("failed with %s (%v), want %s", got, err, want)
	}
	// At least one side is a wildcard: both agree the operation fails, and
	// neither backend defines how.
	return false, nil
}

func (r *runner) step(op Op) error {
	switch op.Code {
	case OpNop:
		return nil
	case OpOpenFile:
		return r.openFile(op)
	case OpCloseFile:
		return r.closeFile(op)
	case OpRead:
		return r.read(op)
	case OpReadAt:
		return r.readAt(op)
	case OpWrite, OpWriteString:
		return r.write(op)
	case OpWriteAt:
		return r.writeAt(op)
	case OpSeek:
		return r.seek(op)
	case OpTruncate:
		return r.truncate(op)
	case OpSync:
		return r.sync(op)
	case OpStat:
		return r.stat(op)
	case OpMkdir:
		return r.mkdir(op)
	case OpRemove:
		return r.remove(op)
	case OpRename:
		return r.rename(op)
	case OpOpenDir:
		return r.openDir(op)
	case OpCloseDir:
		return r.closeDir(op)
	case OpReadNext:
		return r.readNext(op)
	case OpForEachFile:
		return r.forEachFile(op)
	case OpRewind:
		return r.rewind(op)
	}
	return nil
}

// grewOverHole records that a file gained bytes between oldSize and the new end
// without anything having written them. On a backend that zero-fills, that is
// unremarkable and the model already has it right. On one where holes read back
// as whatever was on the media (see Caps.HolesAreGarbage), the model has no idea
// what those bytes are, so the file's content stops being checkable — see
// mnode.tainted.
func (r *runner) grewOverHole(n *mnode, oldSize, newEnd int64) {
	if r.caps.HolesAreGarbage && newEnd > oldSize {
		n.tainted = true
	}
}

// markDirty records a change to the tree, invalidating every open directory
// handle. Iterating a directory whose contents changed under it is undefined on
// both backends, so those handles stop being checkable.
func (r *runner) markDirty() {
	for i := range r.dirty {
		if r.m.dirs[i].state == hsOpen {
			r.dirty[i] = true
		}
	}
}

// adoptFile reclaims slots whose *File the pool has just handed back out. This
// is not a hypothetical: [filesystem.File] is pooled, so the pointer a closed
// slot still holds can be recycled into a later open, at which point the two
// slots alias and the "closed" one would appear to work. The model would be
// right to call that a bug — but the bug would be this harness's, not the
// filesystem's, so the stale slot is dropped instead.
func (r *runner) adoptFile(slot int, f *filesystem.File) {
	for i := range r.files {
		if i != slot && r.files[i] == f {
			r.files[i] = nil
			r.m.files[i] = mfile{}
		}
	}
	r.files[slot] = f
}

func (r *runner) adoptDir(slot int, d *filesystem.Dir) {
	for i := range r.dirs {
		if i != slot && r.dirs[i] == d {
			r.dirs[i] = nil
			r.m.dirs[i] = mdir{}
			r.dirty[i] = false
		}
	}
	r.dirs[slot] = d
}

func (r *runner) openFile(op Op) error {
	slot, p, flag := op.FileSlot(), op.SrcPath(), op.OpenFlags()

	// Reusing an occupied slot would drop a live *File without closing it, which
	// leaks it out of the pool. That is the harness misbehaving, not the
	// filesystem, so the operation is skipped.
	if r.m.files[slot].state == hsOpen {
		return nil
	}
	want, off := r.m.wantOpen(p, flag)
	// A second live handle on one path is undefined on both backends.
	if want == classOK && !r.caps.AliasedOpen && r.m.openHandles(p) > 0 {
		return nil
	}

	created := !r.m.exists(p)
	f, err := r.fsys.OpenFile(p, flag, 0o666)
	ok, failure := r.check(want, err)
	if failure != nil || !ok {
		return failure
	}
	r.adoptFile(slot, f)
	r.m.applyOpen(slot, p, flag, off)
	if created {
		r.markDirty()
	}
	return nil
}

func (r *runner) closeFile(op Op) error {
	slot := op.FileSlot()
	f := r.files[slot]
	if f == nil {
		return nil // Never opened: there is nothing to call Close on.
	}
	want := classClosed
	if r.m.files[slot].state == hsOpen {
		want = classOK
	}
	ok, failure := r.check(want, f.Close())
	if failure != nil {
		return failure
	}
	if ok {
		// The slot keeps its *File on purpose: the next operation on it must hit
		// the poison guard in (*filesystem.File) and report fs.ErrClosed.
		r.m.files[slot].state = hsClosed
	}
	return nil
}

// fileFor resolves a file slot, returning the model's expectation for a slot
// that is closed rather than open. It reports skip when the slot was never
// opened at all and there is simply nothing to call.
func (r *runner) fileFor(op Op) (f *filesystem.File, mf *mfile, skip bool) {
	slot := op.FileSlot()
	f = r.files[slot]
	if f == nil {
		return nil, nil, true
	}
	return f, &r.m.files[slot], false
}

// closedCheck handles the closed-handle case shared by every file operation:
// once a File is closed, every method on it must report fs.ErrClosed, and that
// is exact — it is this package's own guard, not a backend's error code.
func (r *runner) closedCheck(mf *mfile, err error) (handled bool, failure error) {
	if mf.state != hsClosed {
		return false, nil
	}
	_, failure = r.check(classClosed, err)
	return true, failure
}

func (r *runner) read(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	n := op.Len()
	buf := r.buf[:n]
	got, err := f.Read(buf)

	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}
	if n == 0 {
		// A zero-length read is not required to touch the file at all, so it may
		// legally return (0, nil) or (0, io.EOF) — even on a handle it would have
		// refused to read from. Nothing here is checkable.
		return nil
	}
	if !mf.readable() && !r.caps.ReadIgnoresAccessMode {
		// Reading a write-only handle must fail, but neither backend maps the
		// refusal onto a sentinel.
		_, failure := r.check(classOther, err)
		return failure
	}

	data := r.m.node(mf.path).data
	avail := max(int64(len(data))-mf.off, 0)
	want := int(min(int64(n), avail))
	if want == 0 {
		// Nothing left: this must be reported as EOF, not as a silent zero-byte
		// success, or io.ReadAll over this file would spin forever.
		if _, failure := r.check(classEOF, err); failure != nil {
			return failure
		}
		if got != 0 {
			return r.fail("read %d bytes at EOF, want 0", got)
		}
		return nil
	}
	if ok, failure := r.check(classOK, err); failure != nil || !ok {
		return failure
	}
	if got != want {
		return r.fail("read %d bytes at offset %d of a %d byte file, want %d",
			got, mf.off, len(data), want)
	}
	if node := r.m.node(mf.path); !node.tainted {
		if exp := data[mf.off : mf.off+int64(got)]; !bytes.Equal(buf[:got], exp) {
			return r.fail("read wrong bytes at offset %d: got %x, want %x", mf.off, buf[:got], exp)
		}
	}
	mf.off += int64(got)
	return nil
}

func (r *runner) readAt(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	n, off := op.Len(), op.Off()
	buf := r.buf[:n]
	got, err := f.ReadAt(buf, off)

	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}
	if (!mf.readable() && !r.caps.ReadIgnoresAccessMode) || off < 0 {
		_, failure := r.check(classOther, err)
		return failure
	}

	data := r.m.node(mf.path).data
	avail := max(int64(len(data))-off, 0)
	want := int(min(int64(n), avail))
	if want < n {
		// io.ReaderAt is explicit: a short ReadAt must return a non-nil error.
		// Returning (short, nil) would make io.ReadFull-style callers spin.
		if err == nil {
			return r.fail("short ReadAt returned %d of %d bytes with a nil error", got, n)
		}
		if _, failure := r.check(classEOF, err); failure != nil {
			return failure
		}
	} else if ok, failure := r.check(classOK, err); failure != nil || !ok {
		return failure
	}
	if got != want {
		return r.fail("ReadAt %d bytes at offset %d of a %d byte file, want %d",
			got, off, len(data), want)
	}
	if got > 0 && !r.m.node(mf.path).tainted {
		// Only slice once there is something to slice: off may legitimately be
		// far past the end of the file, where data[off:off] would panic.
		if exp := data[off : off+int64(got)]; !bytes.Equal(buf[:got], exp) {
			return r.fail("ReadAt wrong bytes at offset %d: got %x, want %x", off, buf[:got], exp)
		}
	}
	// ReadAt must not disturb the seek offset. The model does not touch mf.off,
	// so a backend that does is caught by the next Read.
	return nil
}

// write covers OpWrite and OpWriteString, which differ only in how the bytes are
// handed to the implementation.
func (r *runner) write(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	n := op.Len()

	// Where the write lands. Both backends put an append handle at the end of
	// the file at open time, but only littlefs re-seeks before every write, so on
	// FAT an intervening Seek sticks and the write lands where the caller left
	// it. See Caps.AppendPerWrite and (*FATFS).mode.
	off := mf.off
	if mf.flag&os.O_APPEND != 0 && r.caps.AppendPerWrite && mf.state == hsOpen {
		// littlefs moves an append handle to the end only when it is BEHIND the
		// end — lfs_file_write guards the move with (file->pos < file->ctz.size).
		// A handle seeked PAST the end therefore writes where it was left,
		// sparsely, rather than being dragged back to the end of the file. This is
		// not a detail worth guessing at: it is the difference between a 45 byte
		// file and a 12 KiB one.
		if size := int64(len(r.m.node(mf.path).data)); off < size {
			off = size
		}
	}

	buf := r.wbuf[:n]
	fillContent(buf, r.idx, off)

	var got int
	var err error
	if op.Code == OpWriteString {
		got, err = f.WriteString(string(buf))
	} else {
		got, err = f.Write(buf)
	}

	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}
	if !mf.writable() {
		_, failure := r.check(classOther, err)
		return failure
	}
	if err != nil {
		// A failed write may still have written some of its bytes, and the most
		// likely reason for one is a full device. Either way the model can no
		// longer be trusted to match.
		if classify(err).strict() {
			return r.fail("write failed with %s (%v), want success", classify(err), err)
		}
		r.poison()
		return nil
	}
	if got != n {
		// A short write with a nil error is how FatFs reports a full disk. It is
		// not something the model can absorb, so stop here rather than pretend.
		r.poison()
		return nil
	}
	node := r.m.node(mf.path)
	r.grewOverHole(node, int64(len(node.data)), off) // The gap the write skipped over.
	node.writeAt(buf, off)
	mf.off = off + int64(got)
	return nil
}

func (r *runner) writeAt(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	n, off := op.Len(), op.Off()
	buf := r.wbuf[:n]
	fillContent(buf, r.idx, off)
	got, err := f.WriteAt(buf, off)

	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}
	if !mf.writable() || off < 0 {
		_, failure := r.check(classOther, err)
		return failure
	}
	if err != nil {
		if classify(err).strict() {
			return r.fail("WriteAt failed with %s (%v), want success", classify(err), err)
		}
		r.poison()
		return nil
	}
	if got != n {
		r.poison() // Full device.
		return nil
	}
	node := r.m.node(mf.path)
	r.grewOverHole(node, int64(len(node.data)), off) // The gap the write skipped over.
	node.writeAt(buf, off)
	// WriteAt must not disturb the seek offset either.
	return nil
}

func (r *runner) seek(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	off, whence := op.Off(), op.Whence()
	got, err := f.Seek(off, whence)

	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}

	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = mf.off
	case io.SeekEnd:
		base = int64(len(r.m.node(mf.path).data))
	}
	want := base + off
	if want < 0 {
		// Seeking to a negative offset must fail. An implementation that instead
		// stores it and indexes a slice with it later is precisely the kind of
		// latent panic this fuzzer is built to surface.
		_, failure := r.check(classOther, err)
		return failure
	}

	// Seeking past the end is legal on os and on littlefs: the position simply
	// goes there, and the hole materializes only when something writes into it.
	//
	// QUARANTINED BUG (FAT). FatFs f_lseek will not let the position exceed the
	// size, and papers over the difference in two incompatible ways depending on
	// how the file was opened: on a writable handle it EXTENDS the file to the
	// requested offset, and on a read-only one it silently CLIPS the seek back to
	// the end. Both come from the same place, so both live behind one flag. See
	// Caps.SeekBoundedBySize.
	node := r.m.node(mf.path)
	grow := int64(-1)
	if r.caps.SeekBoundedBySize && want > int64(len(node.data)) {
		if mf.writable() {
			grow = want
		} else {
			want = int64(len(node.data))
		}
	}

	if ok, failure := r.check(classOK, err); failure != nil || !ok {
		return failure
	}
	if got != want {
		return r.fail("seek returned offset %d, want %d", got, want)
	}
	mf.off = want
	if grow >= 0 {
		// The bytes FAT just added to the file were never written by anyone.
		r.grewOverHole(node, int64(len(node.data)), grow)
		node.truncate(grow)
	}
	return nil
}

func (r *runner) truncate(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	size := op.Size()
	err := f.Truncate(size)

	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}
	if !mf.writable() || size < 0 {
		_, failure := r.check(classOther, err)
		return failure
	}
	if err != nil {
		if classify(err).strict() {
			return r.fail("truncate failed with %s (%v), want success", classify(err), err)
		}
		r.poison() // Growing a file can run the device out of space.
		return nil
	}
	// Truncate resizes the file but does not move the offset, so a handle left
	// past the new end reads EOF and writes into the hole.
	node := r.m.node(mf.path)
	r.grewOverHole(node, int64(len(node.data)), size)
	node.truncate(size)
	if r.caps.TruncateMovesOffset && mf.off > size {
		// QUARANTINED BUG (FAT). FatFs clamps the file pointer to the new size.
		// os and littlefs leave it where the caller put it, so a truncate followed
		// by a write puts the bytes where the caller asked for them rather than at
		// the new end. See Caps.TruncateMovesOffset.
		mf.off = size
	}
	return nil
}

func (r *runner) sync(op Op) error {
	f, mf, skip := r.fileFor(op)
	if skip {
		return nil
	}
	err := f.Sync()
	if handled, failure := r.closedCheck(mf, err); handled {
		return failure
	}
	if err != nil && classify(err).strict() {
		return r.fail("sync failed with %s (%v), want success", classify(err), err)
	} else if err != nil {
		r.poison()
	}
	return nil
}

func (r *runner) stat(op Op) error {
	p := op.SrcPath()
	info, err := r.fsys.Stat(p)

	want := classOK
	n := r.m.node(p)
	switch {
	case r.m.nameTooLong(p):
		want = classOther
	case n == nil || !n.exists:
		want = classNotExist
	}
	if ok, failure := r.check(want, err); failure != nil || !ok {
		return failure
	}
	if info.IsDir() != n.dir {
		return r.fail("stat %q: IsDir() = %v, want %v", p, info.IsDir(), n.dir)
	}
	if n.dir {
		return nil // Directory sizes are the backend's business.
	}
	if r.m.openHandles(p) > 0 {
		// A file with a live handle may have writes that have not reached the
		// directory entry yet, so its recorded size is legitimately stale. Only
		// the file's existence and type are checkable here.
		return nil
	}
	if info.Size() != int64(len(n.data)) {
		return r.fail("stat %q: size %d, want %d", p, info.Size(), len(n.data))
	}
	return nil
}

func (r *runner) mkdir(op Op) error {
	p := op.SrcPath()
	err := r.fsys.Mkdir(p)

	want := classOK
	switch {
	case r.m.nameTooLong(p):
		want = classOther
	case r.m.exists(p):
		want = classExist
	case !r.m.parentExists(p):
		want = classNotExist
	case !r.m.parentOK(p):
		want = classOther // The parent is a regular file.
	}
	if ok, failure := r.check(want, err); failure != nil || !ok {
		return failure
	}
	node := r.m.node(p)
	node.exists, node.dir = true, true
	r.markDirty()
	return nil
}

func (r *runner) remove(op Op) error {
	p := op.SrcPath()
	if r.m.key(p) == "/" {
		return nil // Removing the root is not something either backend defines.
	}
	// Removing a file that still has a live handle is a POSIX trick neither
	// backend supports.
	if !r.caps.RemoveOpen && r.m.openHandles(p) > 0 {
		return nil
	}
	err := r.fsys.Remove(p)

	n := r.m.node(p)
	want := classOK
	switch {
	case r.m.nameTooLong(p):
		want = classOther
	case n == nil || !n.exists:
		want = classNotExist
	case n.dir && len(r.m.childrenOf(p)) > 0:
		want = classOther // Directory not empty: not mapped to a sentinel.
	}
	if ok, failure := r.check(want, err); failure != nil || !ok {
		return failure
	}
	n.exists = false
	n.data = n.data[:0]
	r.markDirty()
	return nil
}

// rename is kept on a short leash. Renaming onto an existing name, renaming a
// directory, and renaming anything with a live handle are all either undefined
// or divergent across the two backends, so they are skipped. What is left — move
// a closed regular file to a free name, and fail to move one that is not there —
// is well defined on both, and is checked strictly.
func (r *runner) rename(op Op) error {
	src, dst := op.SrcPath(), op.DstPath()
	srcKey, dstKey := r.m.key(src), r.m.key(dst)
	if srcKey == dstKey || srcKey == "/" || dstKey == "/" {
		return nil
	}
	srcNode, dstNode := r.m.node(src), r.m.node(dst)
	switch {
	case srcNode.exists && srcNode.dir:
		return nil // Renaming a directory: skipped, see above.
	case dstNode.exists && !r.caps.RenameOverwrite:
		return nil
	case r.m.openHandles(src) > 0 || r.m.openHandles(dst) > 0:
		return nil
	}

	err := r.fsys.Rename(src, dst)

	want := classOK
	switch {
	case r.m.nameTooLong(src) || r.m.nameTooLong(dst):
		want = classOther
	case !srcNode.exists:
		want = classNotExist
	case !r.m.parentExists(dst):
		want = classNotExist // Destination directory is missing.
	case !r.m.parentOK(dst):
		want = classOther // Destination's parent is a regular file.
	}
	if ok, failure := r.check(want, err); failure != nil || !ok {
		return failure
	}
	// Move the contents across, then reuse the source node's buffer rather than
	// dropping it: both nodes live in the model's fixed array for the whole run.
	dstNode.exists, dstNode.dir = true, srcNode.dir
	dstNode.data = append(dstNode.data[:0], srcNode.data...)
	srcNode.exists = false
	srcNode.data = srcNode.data[:0]
	r.markDirty()
	return nil
}

func (r *runner) openDir(op Op) error {
	slot, p := op.DirSlot(), op.SrcPath()
	if r.m.dirs[slot].state == hsOpen {
		return nil // Would leak the live handle out of the pool.
	}
	n := r.m.node(p)
	want := classOK
	switch {
	case r.m.nameTooLong(p):
		want = classOther
	case n == nil || !n.exists:
		want = classNotExist
	case !n.dir:
		want = classOther // Opening a regular file as a directory.
	}
	if want == classOK && !r.caps.AliasedOpen && r.m.openHandles(p) > 0 {
		return nil
	}

	d, err := r.fsys.OpenDir(p)
	ok, failure := r.check(want, err)
	if failure != nil || !ok {
		return failure
	}
	r.adoptDir(slot, d)
	r.m.dirs[slot] = mdir{state: hsOpen, path: p, seen: map[string]bool{}}
	r.dirty[slot] = false
	return nil
}

func (r *runner) closeDir(op Op) error {
	slot := op.DirSlot()
	d := r.dirs[slot]
	if d == nil {
		return nil
	}
	want := classClosed
	if r.m.dirs[slot].state == hsOpen {
		want = classOK
	}
	ok, failure := r.check(want, d.Close())
	if failure != nil {
		return failure
	}
	if ok {
		r.m.dirs[slot].state = hsClosed
	}
	return nil
}

// dirFor resolves a directory slot for an iteration operation, skipping the ones
// whose result nobody can predict: a handle that was never opened, and a handle
// whose directory changed underneath it.
func (r *runner) dirFor(op Op) (d *filesystem.Dir, md *mdir, skip bool) {
	slot := op.DirSlot()
	d = r.dirs[slot]
	if d == nil {
		return nil, nil, true
	}
	md = &r.m.dirs[slot]
	// Iterating a directory that was modified since it was opened is undefined
	// on both backends — the handle may hold a stale metadata pointer — so a
	// dirty handle is good for nothing but Close.
	if md.state == hsOpen && r.dirty[slot] {
		return nil, nil, true
	}
	return d, md, false
}

func (r *runner) readNext(op Op) error {
	d, md, skip := r.dirFor(op)
	if skip {
		return nil
	}
	info, err := d.ReadNext()
	if md.state == hsClosed {
		_, failure := r.check(classClosed, err)
		return failure
	}
	switch classify(err) {
	case classEOF:
		return nil // Exhausted. Which entry that happens on is the backend's business.
	case classOK:
	default:
		if classify(err).strict() {
			return r.fail("ReadNext failed with %s (%v)", classify(err), err)
		}
		r.poison()
		return nil
	}

	// Listing order is not portable — FAT and littlefs disagree, and littlefs
	// emits "." and ".." where FAT does not — so the oracle checks membership
	// rather than sequence: every entry named must exist, and none may be named
	// twice.
	name := info.Name()
	if name == "." || name == ".." {
		return nil
	}
	if md.seen[name] {
		return r.fail("ReadNext listed %q twice in %q", name, md.path)
	}
	md.seen[name] = true

	child := r.m.node(path.Join(md.path, name))
	if child == nil || !child.exists {
		return r.fail("ReadNext listed %q in %q, which does not exist", name, md.path)
	}
	if info.IsDir() != child.dir {
		return r.fail("ReadNext %q in %q: IsDir() = %v, want %v",
			name, md.path, info.IsDir(), child.dir)
	}
	return nil
}

// forEachFile is the strongest of the directory oracles: it sees the whole
// listing at once, so it can compare it to the model as a set — catching a
// missing entry, which ReadNext one call at a time cannot.
func (r *runner) forEachFile(op Op) error {
	d, md, skip := r.dirFor(op)
	if skip {
		return nil
	}
	r.names = r.names[:0]
	var infoErr error
	err := d.ForEachFile(func(info filesystem.FileInfo) error {
		name := info.Name()
		if name == "." || name == ".." {
			return nil // littlefs emits the dot entries; FAT does not.
		}
		if child := r.m.node(path.Join(md.path, name)); child == nil || !child.exists {
			infoErr = r.fail("listed %q in %q, which does not exist", name, md.path)
		} else if info.IsDir() != child.dir {
			infoErr = r.fail("listed %q in %q: IsDir() = %v, want %v",
				name, md.path, info.IsDir(), child.dir)
		}
		r.names = append(r.names, name)
		return nil
	})
	if md.state == hsClosed {
		_, failure := r.check(classClosed, err)
		return failure
	}
	if ok, failure := r.check(classOK, err); failure != nil || !ok {
		return failure
	}
	if infoErr != nil {
		return infoErr
	}
	got := r.names
	sort.Strings(got)
	want := r.m.childrenOf(md.path)
	if len(got) != len(want) {
		return r.fail("listing of %q has %d entries %q, want %d %q",
			md.path, len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			return r.fail("listing of %q is %q, want %q", md.path, got, want)
		}
	}
	return nil
}

func (r *runner) rewind(op Op) error {
	d, md, skip := r.dirFor(op)
	if skip {
		return nil
	}
	err := d.Rewind()
	if md.state == hsClosed {
		_, failure := r.check(classClosed, err)
		return failure
	}
	if ok, failure := r.check(classOK, err); failure != nil || !ok {
		return failure
	}
	clear(md.seen) // Iteration restarts, so the duplicate check restarts with it.
	return nil
}
