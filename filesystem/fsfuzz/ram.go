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
//
// It is also SPARSE, which is what makes FAT32 affordable. A FAT32 volume cannot
// be smaller than about 32 MiB — the variant is defined by having more than 65525
// clusters — but a fuzz program touches a few hundred blocks of it and leaves the
// rest untouched forever. So a device does not store the blocks it could have.
// It stores the blocks something has actually written, in an arena, and a block
// nobody has written is simply absent and reads as erased media. A 32 MiB FAT32
// device costs about a megabyte, and it costs that whether it is 32 MiB or 32 GiB.
//
// The alternative — a flat [] byte the size of the volume — is what this used to
// be, and it was quietly expensive: an untouched page of a fresh allocation is
// not resident, so it measures as free right up until the collector recycles the
// span underneath it, zeroes it, and faults in all 32 MiB per fuzz worker.
type RAM struct {
	unit int
	nblk int
	// fill is what a block nobody has written reads as: 0xff, an erased flash
	// part. It is not cosmetic. Reading a hole hands the caller whatever is on the
	// media (see [Caps.HolesAreGarbage]), so the value unwritten media reads as is
	// exactly what that bug exposes.
	fill byte

	// slot maps a block to where its bytes live in arena, or -1 if the block has
	// never been written and so has no bytes at all. free holds arena slots whose
	// block was dropped, for reuse — without it the arena would grow with every
	// distinct block a fuzz campaign ever touched rather than with how many are
	// live at once.
	slot  []int32
	arena []byte
	free  []int32

	// pristine is the formatted device Reset restores from. It is shared between
	// every device made from it, never written, and owned by the package.
	pristine *RAM

	// dirty is the list of blocks written or erased since the last Reset, and mark
	// deduplicates it. Restoring only these is what makes Reset cost what the
	// program actually touched rather than the size of the device.
	dirty []int32
	mark  []bool
}

// NewRAM returns a device of units blocks of unit bytes each, erased.
func NewRAM(unit, units int) *RAM {
	bd := &RAM{
		unit: unit,
		nblk: units,
		fill: 0xff,
		slot: make([]int32, units),
		mark: make([]bool, units),
	}
	for i := range bd.slot {
		bd.slot[i] = -1 // Erased: no bytes stored anywhere.
	}
	return bd
}

// newRAMFrom returns a device holding the formatted image src, ready to be Reset
// back to it. Only the blocks src actually wrote are copied — the rest are erased
// media on both sides, and erased media is not stored.
func newRAMFrom(src *RAM) *RAM {
	bd := NewRAM(src.unit, src.nblk)
	bd.pristine = src
	for blk := range src.slot {
		if src.slot[blk] >= 0 {
			copy(bd.materialize(blk), src.block(blk))
		}
	}
	return bd
}

// block returns block blk's bytes, or nil if the block is erased.
func (bd *RAM) block(blk int) []byte {
	s := bd.slot[blk]
	if s < 0 {
		return nil
	}
	off := int(s) * bd.unit
	return bd.arena[off : off+bd.unit]
}

// materialize gives block blk somewhere to live, filled with erased media, and
// returns it. A caller that does not overwrite all of it leaves the rest erased,
// which is what a partial write to a fresh block must look like.
func (bd *RAM) materialize(blk int) []byte {
	if b := bd.block(blk); b != nil {
		return b
	}
	var s int32
	if n := len(bd.free); n > 0 {
		s, bd.free = bd.free[n-1], bd.free[:n-1]
	} else {
		s = int32(len(bd.arena) / bd.unit)
		bd.arena = append(bd.arena, make([]byte, bd.unit)...)
	}
	bd.slot[blk] = s
	b := bd.block(blk)
	fill(b, bd.fill)
	return b
}

// drop returns block blk to erased media, releasing its storage.
func (bd *RAM) drop(blk int) {
	if s := bd.slot[blk]; s >= 0 {
		bd.free = append(bd.free, s)
		bd.slot[blk] = -1
	}
}

// dirtyBlock records that a block changed, so Reset knows to restore it and no
// others.
func (bd *RAM) dirtyBlock(blk int) {
	if bd.pristine == nil || bd.mark[blk] {
		return // Not resettable, or already recorded.
	}
	bd.mark[blk] = true
	bd.dirty = append(bd.dirty, int32(blk))
}

// Reset restores the device to the image it was created from, touching only the
// blocks that changed. It is the whole reason a fuzz iteration is free.
func (bd *RAM) Reset() {
	for _, blk := range bd.dirty {
		bd.mark[blk] = false
		if src := bd.pristine.block(int(blk)); src != nil {
			copy(bd.materialize(int(blk)), src)
		} else {
			// The image never wrote this block, so restoring it means putting it back
			// to erased media — which costs nothing, because erased media is not
			// stored. The storage goes back on the free list for the next program.
			bd.drop(int(blk))
		}
	}
	bd.dirty = bd.dirty[:0]
}

// Erase sets the whole device to the erased state (0xff), as a fresh flash part
// would read.
func (bd *RAM) Erase() { bd.eraseBlocks(0, bd.nblk) }

func (bd *RAM) eraseBlocks(startBlock, numBlocks int) {
	for blk := startBlock; blk < startBlock+numBlocks; blk++ {
		bd.dirtyBlock(blk)
		bd.drop(blk) // Erased media is the absence of data, not data.
	}
}

func (bd *RAM) ReadBlocks(dst []byte, startBlock int64) (int, error) {
	if startBlock < 0 || startBlock*int64(bd.unit)+int64(len(dst)) > int64(bd.nblk*bd.unit) {
		return 0, errors.New("fsfuzz: read out of range")
	}
	blk := int(startBlock)
	for i := 0; i < len(dst); i += bd.unit {
		end := min(i+bd.unit, len(dst))
		if b := bd.block(blk); b != nil {
			copy(dst[i:end], b)
		} else {
			fill(dst[i:end], bd.fill)
		}
		blk++
	}
	return len(dst), nil
}

func (bd *RAM) WriteBlocks(data []byte, startBlock int64) (int, error) {
	if startBlock < 0 || startBlock*int64(bd.unit)+int64(len(data)) > int64(bd.nblk*bd.unit) {
		return 0, errors.New("fsfuzz: write out of range")
	}
	blk := int(startBlock)
	for i := 0; i < len(data); i += bd.unit {
		end := min(i+bd.unit, len(data))
		bd.dirtyBlock(blk)
		copy(bd.materialize(blk), data[i:end])
		blk++
	}
	return len(data), nil
}

func (bd *RAM) EraseBlocks(startBlock, numBlocks int64) error {
	if startBlock < 0 || numBlocks < 0 || startBlock+numBlocks > int64(bd.nblk) {
		return errors.New("fsfuzz: erase out of range")
	}
	bd.eraseBlocks(int(startBlock), int(numBlocks))
	return nil
}

func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}
