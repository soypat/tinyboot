package fsfuzz

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// TestFAT32ImageIsFAT32 guards the geometry the FAT32 harness is built on.
//
// Nothing in a boot sector says "this is FAT32". The driver counts the clusters
// and decides: more than 65525 and it is FAT32, fewer and it is FAT16, and it
// mounts either one without complaint. So a volume a few sectors short is
// silently mounted as FAT16, the FAT32 code paths never execute, and every test
// here passes anyway while fuzzing a filesystem nobody asked for.
//
// fat.Formatter refuses to build such a volume, so this is belt and braces — but
// the belt is what fails if fat32Sectors is ever "tidied" down to a rounder
// number. It recomputes fat's own classification (init_fat) from the bytes of the
// formatted image, so a geometry mistake is a loud failure rather than a silent
// hole in the coverage.
func TestFAT32ImageIsFAT32(t *testing.T) {
	// fat's clustMaxFAT16: a volume with more clusters than this is FAT32. It is
	// 0xFFF5 rather than 0xFFF6 for the reasons FatFs and Microsoft give, which
	// come down to real-world DOS behavior rather than to the spec.
	const clustMaxFAT16 = 0xFFF5

	bd := pristineFAT32()
	boot := make([]byte, fat32SectorSize)
	if _, err := bd.ReadBlocks(boot, 0); err != nil {
		t.Fatal(err)
	}

	// The three things fat's check_fs looks at before it will even consider the
	// volume to be FAT32.
	if boot[0] != 0xeb && boot[0] != 0xe9 && boot[0] != 0xe8 {
		t.Errorf("boot sector does not start with a jump instruction: %#02x", boot[0])
	}
	if got := binary.LittleEndian.Uint16(boot[510:]); got != 0xaa55 {
		t.Errorf("boot signature = %#04x, want 0xaa55", got)
	}
	if got := string(boot[82:90]); got != "FAT32   " {
		t.Errorf("filesystem type string = %q, want %q", got, "FAT32   ")
	}

	// The arithmetic init_fat does, on the bytes as written.
	var (
		bytesPerSec = int(binary.LittleEndian.Uint16(boot[11:]))
		secPerClus  = int(boot[13])
		rsvdSecCnt  = int(binary.LittleEndian.Uint16(boot[14:]))
		numFATs     = int(boot[16])
		rootEntCnt  = int(binary.LittleEndian.Uint16(boot[17:]))
		totSec32    = int(binary.LittleEndian.Uint32(boot[32:]))
		fatSz32     = int(binary.LittleEndian.Uint32(boot[36:]))
	)
	if bytesPerSec != fat32SectorSize {
		t.Fatalf("bytes per sector = %d, want %d", bytesPerSec, fat32SectorSize)
	}
	if rootEntCnt != 0 {
		t.Errorf("root entry count = %d; FAT32 requires 0 and fat rejects anything else", rootEntCnt)
	}
	if got := binary.LittleEndian.Uint16(boot[42:]); got != 0 {
		t.Errorf("FS version = %#04x; fat rejects anything but 0", got)
	}
	if got := binary.LittleEndian.Uint16(boot[48:]); got != 1 {
		t.Errorf("FSInfo sector = %d; fat only reads FSInfo when this is 1", got)
	}

	nonData := rsvdSecCnt + numFATs*fatSz32 + rootEntCnt/(bytesPerSec/32)
	clusters := (totSec32 - nonData) / secPerClus
	if clusters <= clustMaxFAT16 {
		t.Fatalf("the image has %d clusters, which fat will mount as FAT16, not FAT32 "+
			"(it needs more than %d). The fuzzer would run against the wrong filesystem "+
			"and say nothing. Grow fat32Sectors.", clusters, clustMaxFAT16)
	}

	// And the FAT has to be big enough to describe them, or the tail of the volume
	// is unaddressable.
	if need := (clusters + 2) * 4; need > fatSz32*bytesPerSec {
		t.Errorf("each FAT is %d bytes but must hold %d bytes of entries for %d clusters",
			fatSz32*bytesPerSec, need, clusters)
	}
	t.Logf("FAT32: %d clusters of %d B, %d sectors of %d B = %.1f MiB, FAT %d sectors",
		clusters, secPerClus*bytesPerSec, totSec32, bytesPerSec,
		float64(totSec32*bytesPerSec)/(1<<20), fatSz32)
}

// TestFAT32ImageIsSparse pins the memory cost of the FAT32 device.
//
// The image is over 32 MiB because FAT32 cannot be smaller, and there is one per
// fuzz worker. What keeps that affordable is that [RAM] does not store a block
// nobody wrote, so the real cost is the metadata — two FATs and the boot records
// — and not the volume. If this starts failing, every fuzz worker just got tens
// of megabytes more expensive and the machine running the fuzzer is the thing
// that pays.
func TestFAT32ImageIsSparse(t *testing.T) {
	const budget = 2 << 20 // 2 MiB, out of a 32.5 MiB volume.

	bd := pristineFAT32()
	live := 0
	for _, s := range bd.slot {
		if s >= 0 {
			live++
		}
	}
	// The index is part of the cost and has to be counted: it is one int32 per
	// block whether the block exists or not.
	cost := len(bd.arena) + 4*len(bd.slot) + len(bd.mark)
	if cost > budget {
		t.Errorf("a formatted FAT32 device costs %d B, over the %d B budget — and that is "+
			"per fuzz worker, so it is multiplied by the core count", cost, budget)
	}
	t.Logf("FAT32: a %d B volume costs %d B (%d of %d blocks stored, %d B of arena, %d B of index)",
		bd.nblk*bd.unit, cost, live, bd.nblk, len(bd.arena), 4*len(bd.slot))
}

// TestRAMArenaDoesNotCreep is the failure mode a sparse device has that a flat
// one does not.
//
// If Reset dropped a block without returning its storage, the arena would grow
// with every distinct block a fuzz campaign ever touched, and a campaign touches
// a lot of them: bounded in principle by the size of the volume, 32 MiB per
// worker in practice, reached over hours. It would look fine in any short test.
//
// What the arena is allowed to do is ratchet up to the largest working set any
// one program had, and then stop. So the assertion is a hard ceiling rather than
// "it did not grow", which would fail the moment a program touched one block more
// than its predecessors.
func TestRAMArenaDoesNotCreep(t *testing.T) {
	const budget = 1 << 20 // The formatted image is 529 KB of it.

	rng := rand.New(rand.NewSource(1))
	h := GetFAT32()
	defer h.Release()

	warm := 0
	for i := range 500 {
		if err := h.Run(GenProgram(rng, 64)); err != nil {
			t.Fatalf("program %d: %v", i, err)
		}
		if err := h.prepare(); err != nil { // What Get does between programs.
			t.Fatal(err)
		}
		if i == 100 {
			warm = len(h.bd.arena)
		}
	}
	if got := len(h.bd.arena); got > budget {
		t.Errorf("after 500 programs the arena holds %d B, over the %d B budget: Reset is "+
			"dropping blocks without returning their storage, and this is a leak that ends "+
			"at 32 MiB per fuzz worker", got, budget)
	}
	t.Logf("arena: %d B after 100 programs, %d B after 500", warm, len(h.bd.arena))
}

// TestRAMSparseReadsErased is the invariant the sparse device rests on: a block
// nobody has written must read as erased media, exactly as if it had been
// written full of 0xff. If it read as zeros instead, Caps.HolesAreGarbage would
// look fixed when it is not — a hole would come back zero-filled and the fuzzer
// would stop looking for the bug that is still there.
func TestRAMSparseReadsErased(t *testing.T) {
	const unit, units = 512, 8
	bd := NewRAM(unit, units)

	buf := make([]byte, unit)
	if _, err := bd.ReadBlocks(buf, 3); err != nil {
		t.Fatal(err)
	}
	for i, b := range buf {
		if b != 0xff {
			t.Fatalf("unwritten block reads %#02x at byte %d, want 0xff (erased flash)", b, i)
		}
	}

	// A partial write has to materialize the whole block, or the bytes it did not
	// cover would read back as zeros.
	if _, err := bd.WriteBlocks([]byte{1, 2, 3}, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := bd.ReadBlocks(buf, 3); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 1 || buf[1] != 2 || buf[2] != 3 {
		t.Fatalf("partial write did not land: %v", buf[:3])
	}
	for i, b := range buf[3:] {
		if b != 0xff {
			t.Fatalf("the part of the block the write did not cover reads %#02x at byte %d, want 0xff", b, i+3)
		}
	}
}

// TestRAMResetRestoresImage checks the other half: Reset puts back what the image
// held, including for blocks the image never wrote — which have to go back to
// being erased rather than keeping what the last program left in them. A device
// that leaked state across a Reset would make every fuzz finding suspect, because
// the failing input would no longer reproduce on its own.
func TestRAMResetRestoresImage(t *testing.T) {
	src := NewRAM(512, 8)
	if _, err := src.WriteBlocks([]byte{0xaa}, 1); err != nil { // A "formatted" block.
		t.Fatal(err)
	}
	bd := newRAMFrom(src)

	if _, err := bd.WriteBlocks([]byte{0xbb}, 1); err != nil { // Overwrite the image's block.
		t.Fatal(err)
	}
	if _, err := bd.WriteBlocks([]byte{0xcc}, 5); err != nil { // Write a block the image never wrote.
		t.Fatal(err)
	}
	bd.Reset()

	buf := make([]byte, 1)
	if _, err := bd.ReadBlocks(buf, 1); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0xaa {
		t.Errorf("block 1 reads %#02x after Reset, want the image's 0xaa", buf[0])
	}
	if _, err := bd.ReadBlocks(buf, 5); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0xff {
		t.Errorf("block 5 reads %#02x after Reset, want 0xff: the image never wrote it, "+
			"so resetting it means erasing it", buf[0])
	}
	if len(bd.dirty) != 0 {
		t.Errorf("Reset left %d blocks marked dirty", len(bd.dirty))
	}
}
