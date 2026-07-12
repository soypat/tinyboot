package fsfuzz

import "math/rand"

// This file is the ONLY place in the package that may import math/rand, and it
// is deliberately on the far side of the encoding from [Run].
//
// The rule this enforces is the whole reason the package is shaped the way it
// is. A fuzz target that draws randomness while it executes makes its corpus a
// function of its own source code: add one Rand call in the middle of a test and
// every later call returns a different value, so every recorded input now
// describes a different program and the accumulated corpus is worthless. Here,
// randomness only ever authors *bytes*. Those bytes are the artifact. What they
// mean is fixed by [Decode], which no amount of new checks in [Run] can perturb.
//
// So: use rand freely to make inputs. Never to make decisions.

// GenBytes returns a random encoded program of up to maxOps operations, ready to
// hand to [Decode]. It is used to seed a corpus and to drive the deterministic
// randomized test, neither of which is the fuzz target itself.
func GenBytes(rng *rand.Rand, maxOps int) []byte {
	return GenProgram(rng, maxOps).Encode()
}

// GenProgram builds a random program biased toward the states worth reaching.
//
// A uniformly random program is nearly worthless here: it spends most of its
// operations on handles that were never opened and paths that were never
// created, so it never gets deep enough to find anything. The biases below exist
// to push it into the interesting region — files that exist, handles that are
// open, offsets near a boundary — while the *shape* of the bias stays outside
// the target, where changing it costs nothing but a regenerated seed corpus.
func GenProgram(rng *rand.Rand, maxOps int) Program {
	n := 1 + rng.Intn(maxOps)
	prog := make(Program, 0, n)
	for range n {
		prog = append(prog, genOp(rng))
	}
	return prog
}

func genOp(rng *rand.Rand) Op {
	// Draw the opcode through the table, so the generated mix matches the mix the
	// fuzzer's own mutations produce. One weighting, one place.
	code := opTable[rng.Intn(OpTableLen)]
	o := Op{
		Code:  code,
		Slot:  uint8(rng.Intn(NumFiles)),
		PathA: uint8(rng.Intn(len(Paths))),
		PathB: uint8(rng.Intn(len(Paths))),
		Flags: genFlags(rng),
		Aux:   uint8(rng.Intn(256)),
	}
	switch code {
	case OpSeek, OpTruncate, OpReadAt, OpWriteAt:
		o.Arg = uint16(genOffset(rng))
	default:
		o.Arg = uint16(genLen(rng))
	}
	return o
}

// genFlags favors flag combinations that open a file successfully. A uniformly
// random flags byte is rejected outright about a third of the time — bad access
// mode, O_EXCL without O_CREATE, the unsupported O_SYNC bit — and a program that
// never manages to open anything never writes anything either. The rejected
// combinations still appear, just not on most of the opens.
func genFlags(rng *rand.Rand) uint8 {
	if rng.Intn(8) == 0 {
		return uint8(rng.Intn(256)) // Anything at all, including the invalid encodings.
	}
	flags := uint8(1 + rng.Intn(2)) // O_WRONLY or O_RDWR: an open worth doing.
	for _, bit := range []uint8{1 << 2, 1 << 3, 1 << 4, 1 << 5} {
		if rng.Intn(3) == 0 {
			flags |= bit
		}
	}
	if flags&(1<<3) != 0 {
		flags |= 1 << 2 // O_EXCL is only legal with O_CREATE; make it so most of the time.
	}
	return flags
}

// genLen favors small reads and writes, plus the sizes that sit on a boundary
// the backends care about: a FAT sector, a littlefs page, an erase block.
func genLen(rng *rand.Rand) int {
	switch rng.Intn(4) {
	case 0:
		return rng.Intn(8) // Tiny: the inline-file path on littlefs.
	case 1:
		boundaries := [...]int{0, 1, 255, 256, 511, 512, 513, 4095, 4096}
		return boundaries[rng.Intn(len(boundaries))]
	case 2:
		return rng.Intn(MaxIO + 1)
	}
	return rng.Intn(600)
}

// genOffset produces the signed argument of a seek, truncate or positional
// read/write, biased toward zero, toward the boundaries, and toward negative
// values — which must be rejected, and which are what a backend that indexes a
// slice without checking will panic on.
func genOffset(rng *rand.Rand) int16 {
	switch rng.Intn(4) {
	case 0:
		return int16(rng.Intn(16) - 4) // Around zero, including a few negatives.
	case 1:
		boundaries := [...]int16{-1, 0, 1, 255, 256, 511, 512, 4095, 4096, -512, 32767, -32768}
		return boundaries[rng.Intn(len(boundaries))]
	case 2:
		return int16(rng.Intn(2048))
	}
	return int16(rng.Intn(65536) - 32768)
}
