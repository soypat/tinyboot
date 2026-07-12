// Package fsfuzz is a fuzzing and conformance kit for [filesystem]
// implementations. It decodes an arbitrary byte string into a [Program] — an
// explicit list of filesystem operations — and runs that program against both a
// real filesystem and an in-memory reference model, failing on any disagreement.
//
// # Why the encoding looks like this
//
// The obvious way to write a stateful fuzz target is to pull entropy from the
// input as you go: read a byte to pick an operation, read another to pick its
// argument, and so on. Do not. That makes the corpus a hostage of the target's
// source code. Insert one extra read anywhere and every byte downstream of it
// changes meaning, so every regression file in testdata/fuzz decodes to a
// different program than the one that was recorded, and the accumulated corpus —
// which is the only thing a fuzzer really owns — silently rots.
//
// This package separates entropy from execution with a stable data structure:
//
//	bytes --Decode--> Program --Run--> filesystem + model
//
// [Decode] is the only thing that ever looks at the input, and it is a pure,
// total, fixed-width function. [Run] is deterministic and consumes no input, so
// adding a check, an oracle or a whole new invariant to it can never invalidate
// a corpus. Randomness lives outside the target entirely, in [GenProgram], whose
// output is bytes — an artifact, not a decision made mid-test.
//
// # The corpus stability contract
//
// A program is a version byte followed by fixed-width 8-byte records:
//
//	[0] opcode -> opTable[b%OpTableLen]
//	[1] handle slot
//	[2] path A index -> Paths[b%len(Paths)]
//	[3] path B index (rename destination; unused by every other op)
//	[4] open flags, packed (see Op.OpenFlags)
//	[5] arg low  -+ uint16, meaning fixed per opcode (see Op.Arg)
//	[6] arg high -+
//	[7] aux (seek whence; otherwise reserved)
//
// Four rules keep an old corpus meaningful against a newer target. They are
// enforced by TestCorpusStable, which is the only reason they are more than a
// comment:
//
//  1. [RecordSize] is 8 and never changes.
//  2. [OpTableLen] is 64 and never changes. Entries in opTable are never
//     reordered and never removed. A new operation takes the next reserved slot:
//     corpus bytes that landed there used to decode to [OpNop] and now decode to
//     the new operation, while every other record in every corpus file keeps its
//     exact meaning. That locality is the whole point.
//  3. A byte's meaning is fixed per (opcode, position). A new argument comes out
//     of a reserved byte; it never shifts an existing one.
//  4. Nothing reachable from Decode or Run may call rand, iterate a map for
//     behavior, read the clock, or start a goroutine.
//
// Fixed-width records pay a second dividend: Go's fuzz minimizer shrinks a
// failure by deleting byte ranges, and on an 8-byte grid a deletion is a dropped
// operation rather than a corrupted one, so minimized failures stay readable.
// See [Program.String].
package fsfuzz

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Wire format constants. Changing any of these invalidates every corpus file in
// existence; see the contract in the package documentation.
const (
	// Version is the first byte of an encoded program. Decode is total, so an
	// unrecognized version is not an error: it falls back to the v1 layout. A
	// future incompatible layout gets a new version and a new decode path, and
	// the old corpus keeps decoding through the old one.
	Version = 1

	// RecordSize is the encoded width of one [Op], in bytes.
	RecordSize = 8

	// OpTableLen is the number of opcode slots. The dispatch is b%OpTableLen, so
	// this length is part of the wire format.
	OpTableLen = 64

	// MaxOps bounds a decoded program. A fuzzer that discovers it can make the
	// target quadratic by submitting a megabyte of records will do so.
	MaxOps = 512

	// MaxIO caps a single read or write, so one record cannot ask for a
	// gigabyte-long buffer.
	MaxIO = 4096

	// NumFiles and NumDirs size the handle tables. Small on purpose: with four
	// file slots and a sixteen-path alphabet the fuzzer trips over aliasing,
	// use-after-close and double-open constantly, which is where the bugs are.
	NumFiles = 4
	NumDirs  = 2
)

// Opcode is what a record's first byte selects, through opTable.
type Opcode uint8

// The operation set, mirroring the pooled API of [filesystem.FS], [filesystem.File]
// and [filesystem.Dir].
//
// These constants are an internal numbering, not the wire format — opTable is
// the wire format — so they may be reordered freely. Only opTable may not.
const (
	OpNop Opcode = iota
	OpOpenFile
	OpCloseFile
	OpRead
	OpReadAt
	OpWrite
	OpWriteAt
	OpWriteString
	OpSeek
	OpTruncate
	OpSync
	OpStat
	OpMkdir
	OpRemove
	OpRename
	OpOpenDir
	OpCloseDir
	OpReadNext
	OpForEachFile
	OpRewind
	numOpcodes
)

var opNames = [numOpcodes]string{
	OpNop: "nop", OpOpenFile: "open", OpCloseFile: "close",
	OpRead: "read", OpReadAt: "readat", OpWrite: "write", OpWriteAt: "writeat",
	OpWriteString: "writestr", OpSeek: "seek", OpTruncate: "truncate", OpSync: "sync",
	OpStat: "stat", OpMkdir: "mkdir", OpRemove: "remove", OpRename: "rename",
	OpOpenDir: "opendir", OpCloseDir: "closedir", OpReadNext: "readnext",
	OpForEachFile: "foreach", OpRewind: "rewind",
}

func (op Opcode) String() string {
	if op >= numOpcodes {
		return "op(" + strconv.Itoa(int(op)) + ")"
	}
	return opNames[op]
}

// opTable is the wire format: record byte 0 indexes it modulo [OpTableLen]. An
// opcode's share of the table is its probability of being generated, which is
// how the operation mix is biased without a single call to rand.
//
// APPEND ONLY. Never reorder an entry, never remove one, never change the length.
// A new operation replaces the FIRST reserved slot — the ones left implicitly
// zero ([OpNop]) at the end — and nothing else moves. See the package docs.
var opTable = [OpTableLen]Opcode{
	OpOpenFile, OpOpenFile, OpOpenFile, OpOpenFile, OpOpenFile, OpOpenFile,
	OpCloseFile, OpCloseFile, OpCloseFile,
	OpRead, OpRead, OpRead, OpRead,
	OpReadAt, OpReadAt,
	OpWrite, OpWrite, OpWrite, OpWrite, OpWrite,
	OpWriteAt, OpWriteAt,
	OpWriteString, OpWriteString,
	OpSeek, OpSeek, OpSeek,
	OpTruncate, OpTruncate,
	OpSync,
	OpStat, OpStat, OpStat,
	OpMkdir, OpMkdir,
	OpRemove, OpRemove, OpRemove,
	OpRename, OpRename,
	OpOpenDir, OpOpenDir,
	OpCloseDir,
	OpReadNext, OpReadNext,
	OpForEachFile, OpForEachFile,
	OpRewind,
	// Slots 48..63 are RESERVED and decode to OpNop. New operations go here, one
	// at a time, in order.
}

// Paths is the path alphabet, indexed by a record's path bytes modulo its
// length. It is deliberately tiny: a fuzzer given a large namespace spends its
// budget creating files nothing ever touches again, whereas a fuzzer given eight
// names collides on them constantly, and collisions — reopen, rename onto,
// remove while open — are where filesystems break.
//
// Every name is lowercase because FAT casefolds and littlefs does not; a
// mixed-case alphabet would manufacture divergences that say nothing about
// either implementation. Adversarial paths (empty, trailing slash, "..") are
// deliberately absent: they belong in the stateless FuzzPaths target, where the
// oracle is simply "do not panic". Putting them here would only force the model
// to take a position on behavior neither backend actually defines.
var Paths = [16]string{
	0:  "/",
	1:  "/a",
	2:  "/b",
	3:  "/c",
	4:  "/d",
	5:  "/e",
	6:  "/d/a",
	7:  "/d/b",
	8:  "/d/c",
	9:  "/d/d",
	10: "/d/d/a",
	11: "/d/d/b",
	12: "/e/a",
	13: "/e/b",
	14: "/a/x", // Usually a path through a regular file: must fail, must not panic.
	15: "/" + longName,
}

// longName exceeds the 255-byte name limit of both backends, so every operation
// naming it must fail.
var longName = strings.Repeat("n", 300)

// Op is one decoded record. The raw bytes are kept rather than the interpreted
// values so that Encode round-trips exactly; interpretation lives in the
// accessors below, each of which documents what the byte means for which opcode.
type Op struct {
	Code  Opcode
	Slot  uint8
	PathA uint8
	PathB uint8
	Flags uint8
	Arg   uint16
	Aux   uint8
}

// FileSlot is the file handle this op addresses.
func (o Op) FileSlot() int { return int(o.Slot) % NumFiles }

// DirSlot is the directory handle this op addresses.
func (o Op) DirSlot() int { return int(o.Slot) % NumDirs }

// SrcPath is the path operated on. DstPath is the destination of [OpRename] and
// is meaningless for every other opcode.
func (o Op) SrcPath() string { return Paths[int(o.PathA)%len(Paths)] }
func (o Op) DstPath() string { return Paths[int(o.PathB)%len(Paths)] }

// OpenFlags unpacks byte 4 into the os.O_* bitmask [filesystem.FS.OpenFile]
// takes. The low two bits are the access mode and land on os.O_RDONLY (0),
// os.O_WRONLY (1), os.O_RDWR (2) directly; the fourth combination is
// O_WRONLY|O_RDWR, which is not a valid access mode and which the conversion
// under test is required to reject rather than silently reinterpret.
//
// Bit 6 is os.O_SYNC, which neither backend supports. It is here so the fuzzer
// regularly exercises the unsupported-flag rejection in (*FATFS).mode and
// (*LittleFS).openFlags instead of only ever passing flags that work.
func (o Op) OpenFlags() int {
	flag := int(o.Flags & 3) // O_RDONLY|O_WRONLY|O_RDWR, including the invalid pair.
	for _, f := range [...]struct {
		bit  uint8
		flag int
	}{
		{1 << 2, os.O_CREATE},
		{1 << 3, os.O_EXCL},
		{1 << 4, os.O_TRUNC},
		{1 << 5, os.O_APPEND},
		{1 << 6, os.O_SYNC}, // Unsupported by both backends: must be rejected.
	} {
		if o.Flags&f.bit != 0 {
			flag |= f.flag
		}
	}
	return flag
}

// Len is the byte count of an [OpRead], [OpWrite] or [OpWriteString], and of the
// [OpReadAt] and [OpWriteAt] whose offset comes from Off instead.
func (o Op) Len() int {
	if o.Code == OpReadAt || o.Code == OpWriteAt {
		// The At ops spend Arg on a signed offset, so their length comes from the
		// aux byte and is small. Offset variety matters more than length variety
		// here: bad offset arithmetic is the bug these ops exist to find.
		return int(o.Aux) + 1
	}
	return int(o.Arg) % (MaxIO + 1)
}

// Off is the signed offset of an [OpReadAt] or [OpWriteAt], and the signed
// offset of an [OpSeek]. Signed on purpose: a negative offset must be an error,
// and an implementation that instead indexes a slice with it panics, which is
// exactly the kind of find this package exists for.
func (o Op) Off() int64 { return int64(int16(o.Arg)) }

// Size is the signed argument of an [OpTruncate]. Also signed on purpose.
func (o Op) Size() int64 { return int64(int16(o.Arg)) }

// Whence is the io.Seek* constant of an [OpSeek]. Only three of the aux byte's
// values are meaningful, so it is reduced modulo three rather than passed
// through: an invalid whence is a one-line rejection that neither backend gets
// wrong, and spending two thirds of every seek record on it would be a waste of
// the fuzzer's budget.
func (o Op) Whence() int { return int(o.Aux) % 3 } // io.SeekStart, io.SeekCurrent, io.SeekEnd.

// Program is a decoded sequence of operations.
type Program []Op

// Decode is total: every byte string, including the empty one, is a valid
// program. That is a requirement of the fuzzing engine — it will hand this
// function arbitrary bytes and expects a program back, not an error — and it is
// also what lets the minimizer chop a failing input to pieces without ever
// producing an input the target rejects.
//
// A trailing partial record is zero-padded rather than dropped, so that deleting
// a single byte from a corpus file perturbs one operation rather than shifting
// every operation after it.
func Decode(b []byte) Program {
	if len(b) == 0 {
		return nil
	}
	// b[0] is the version. It is read and ignored: there is only one layout so
	// far, and an unknown version decodes as v1 rather than failing, because a
	// mutator flipping the version byte must not turn every input into a no-op.
	b = b[1:]

	n := (len(b) + RecordSize - 1) / RecordSize
	n = min(n, MaxOps)
	prog := make(Program, 0, n)
	var rec [RecordSize]byte
	for i := 0; i < n; i++ {
		clear(rec[:])
		copy(rec[:], b[i*RecordSize:])
		prog = append(prog, Op{
			Code:  opTable[rec[0]%OpTableLen],
			Slot:  rec[1],
			PathA: rec[2],
			PathB: rec[3],
			Flags: rec[4],
			Arg:   uint16(rec[5]) | uint16(rec[6])<<8,
			Aux:   rec[7],
		})
	}
	return prog
}

// Encode is the inverse of [Decode] for the fields a program carries. It is not
// a byte-for-byte inverse — the opcode byte it emits is the first table slot
// holding that opcode, not necessarily the one the input used — but it satisfies
// Decode(Encode(p)) == p, which is what a seed corpus needs.
func (prog Program) Encode() []byte {
	b := make([]byte, 1, 1+len(prog)*RecordSize)
	b[0] = Version
	for _, o := range prog {
		b = append(b,
			opByte(o.Code), o.Slot, o.PathA, o.PathB, o.Flags,
			byte(o.Arg), byte(o.Arg>>8), o.Aux,
		)
	}
	return b
}

// opByte finds a table slot holding code, so that Encode's output decodes back
// to the same opcode.
func opByte(code Opcode) byte {
	for i, c := range opTable {
		if c == code {
			return byte(i)
		}
	}
	// Only reachable for an opcode with no table slot, which is a programming
	// error in this package, not something an input can cause.
	panic("fsfuzz: opcode " + code.String() + " has no slot in opTable")
}

// String renders a program as the sequence of calls it makes. A failing corpus
// file is forty bytes of noise without this; with it, a fuzz failure reads as a
// test case someone could have written by hand, which is most of what makes a
// find actionable.
func (prog Program) String() string {
	var sb strings.Builder
	for i, o := range prog {
		fmt.Fprintf(&sb, "%3d: %s\n", i, o)
	}
	return sb.String()
}

func (o Op) String() string {
	switch o.Code {
	case OpOpenFile:
		return fmt.Sprintf("open      f%d %q %s", o.FileSlot(), o.SrcPath(), flagString(o.OpenFlags()))
	case OpCloseFile, OpSync:
		return fmt.Sprintf("%-9s f%d", o.Code, o.FileSlot())
	case OpRead, OpWrite, OpWriteString:
		return fmt.Sprintf("%-9s f%d n=%d", o.Code, o.FileSlot(), o.Len())
	case OpReadAt, OpWriteAt:
		return fmt.Sprintf("%-9s f%d n=%d off=%d", o.Code, o.FileSlot(), o.Len(), o.Off())
	case OpSeek:
		return fmt.Sprintf("seek      f%d off=%d whence=%s", o.FileSlot(), o.Off(), whenceString(o.Whence()))
	case OpTruncate:
		return fmt.Sprintf("truncate  f%d size=%d", o.FileSlot(), o.Size())
	case OpStat, OpMkdir, OpRemove:
		return fmt.Sprintf("%-9s %q", o.Code, o.SrcPath())
	case OpRename:
		return fmt.Sprintf("rename    %q -> %q", o.SrcPath(), o.DstPath())
	case OpOpenDir:
		return fmt.Sprintf("opendir   d%d %q", o.DirSlot(), o.SrcPath())
	case OpCloseDir, OpReadNext, OpForEachFile, OpRewind:
		return fmt.Sprintf("%-9s d%d", o.Code, o.DirSlot())
	}
	return o.Code.String()
}

func flagString(flag int) string {
	names := []string{}
	switch flag & 3 {
	case os.O_RDONLY:
		names = append(names, "O_RDONLY")
	case os.O_WRONLY:
		names = append(names, "O_WRONLY")
	case os.O_RDWR:
		names = append(names, "O_RDWR")
	default:
		names = append(names, "O_WRONLY|O_RDWR(invalid)")
	}
	for _, f := range [...]struct {
		flag int
		name string
	}{
		{os.O_CREATE, "O_CREATE"}, {os.O_EXCL, "O_EXCL"}, {os.O_TRUNC, "O_TRUNC"},
		{os.O_APPEND, "O_APPEND"}, {os.O_SYNC, "O_SYNC"},
	} {
		if flag&f.flag != 0 {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, "|")
}

func whenceString(whence int) string {
	switch whence {
	case io.SeekStart:
		return "SEEK_SET"
	case io.SeekCurrent:
		return "SEEK_CUR"
	}
	return "SEEK_END"
}

// content is the byte a file holds at off when written by the record at program
// index idx. Content is derived, never drawn from the input: giving the fuzzer
// control of file bytes would spend most of a record on data the oracle checks
// by construction anyway, and would tempt a future change into reading "just one
// more byte" of entropy per write — the exact move this package is built to
// prevent. Varying it with idx is enough for a backend that writes the wrong
// bytes, or the right bytes to the wrong place, to be caught.
func content(idx int, off int64) byte {
	return byte(idx*31 + int(off)*7 + 13)
}

// fillContent writes the expected content of a write issued by record idx,
// landing at file offset off, into buf.
func fillContent(buf []byte, idx int, off int64) {
	for i := range buf {
		buf[i] = content(idx, off+int64(i))
	}
}
