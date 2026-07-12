package fsfuzz

import (
	"errors"
)

// RAM is an in-memory block device. fat.BlockDevice and lfs.BlockDevice declare
// the same three methods, so one device serves both backends. Blocks are
// addressed in units of unit bytes: a sector for FAT, a page for littlefs.
//
// A RAM device is built to be REUSED, not reallocated. A fuzzer runs one worker
// per core and millions of iterations, so allocating a device per iteration
// means allocating gigabytes per second of multi-megabyte objects: the collector
// cannot keep up, the resident set climbs, and the machine running the fuzzer
// dies before the filesystem under test does. [RAM.Reset] exists so an iteration
// costs no allocation at all — see [Harness].
type RAM struct {
	unit int
	mem  []byte

	// pristine is the formatted image Reset restores from. It is shared, never
	// written, and owned by the package.
	pristine []byte

	// dirty is the list of block indices written or erased since the last Reset,
	// and mark deduplicates it. Restoring only these is what makes Reset cost
	// what the program actually touched rather than the size of the device: a
	// fuzz program writes a few kilobytes, so resetting a 2 MiB device by copying
	// 2 MiB would be three orders of magnitude of pure waste per iteration.
	dirty []int32
	mark  []bool
}

// NewRAM returns a device of units blocks of unit bytes each, erased.
func NewRAM(unit, units int) *RAM {
	bd := &RAM{
		unit: unit,
		mem:  make([]byte, unit*units),
		mark: make([]bool, units),
	}
	bd.erase(0, units)
	return bd
}

// newRAMFrom returns a device holding a copy of the formatted image img, ready
// to be Reset back to it.
func newRAMFrom(unit int, img []byte) *RAM {
	bd := NewRAM(unit, len(img)/unit)
	copy(bd.mem, img)
	bd.pristine = img
	return bd
}

// Reset restores the device to the image it was created from, touching only the
// blocks that changed. It is the whole reason a fuzz iteration is free.
func (bd *RAM) Reset() {
	for _, blk := range bd.dirty {
		off := int(blk) * bd.unit
		copy(bd.mem[off:off+bd.unit], bd.pristine[off:])
		bd.mark[blk] = false
	}
	bd.dirty = bd.dirty[:0]
}

// Erase sets the whole device to the erased state (0xff), as a fresh flash part
// would read.
func (bd *RAM) Erase() { bd.erase(0, len(bd.mem)/bd.unit) }

func (bd *RAM) erase(startBlock, numBlocks int) {
	off, n := startBlock*bd.unit, numBlocks*bd.unit
	for i := off; i < off+n; i++ {
		bd.mem[i] = 0xff
	}
}

// touch records that the bytes in [off, off+n) changed, so Reset knows to
// restore the blocks holding them and no others.
func (bd *RAM) touch(off, n int) {
	if bd.pristine == nil {
		return // Not a resettable device; nothing to track.
	}
	first, last := off/bd.unit, (off+n-1)/bd.unit
	for blk := first; blk <= last; blk++ {
		if !bd.mark[blk] {
			bd.mark[blk] = true
			bd.dirty = append(bd.dirty, int32(blk))
		}
	}
}

func (bd *RAM) ReadBlocks(dst []byte, startBlock int64) (int, error) {
	off := int(startBlock) * bd.unit
	if off < 0 || off+len(dst) > len(bd.mem) {
		return 0, errors.New("fsfuzz: read out of range")
	}
	return copy(dst, bd.mem[off:]), nil
}

func (bd *RAM) WriteBlocks(data []byte, startBlock int64) (int, error) {
	off := int(startBlock) * bd.unit
	if off < 0 || off+len(data) > len(bd.mem) {
		return 0, errors.New("fsfuzz: write out of range")
	}
	bd.touch(off, len(data))
	return copy(bd.mem[off:], data), nil
}

func (bd *RAM) EraseBlocks(startBlock, numBlocks int64) error {
	off, n := int(startBlock)*bd.unit, int(numBlocks)*bd.unit
	if off < 0 || off+n > len(bd.mem) {
		return errors.New("fsfuzz: erase out of range")
	}
	bd.touch(off, n)
	bd.erase(int(startBlock), int(numBlocks))
	return nil
}
