package fsfuzz

import (
	"runtime"
	"sync"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
	"github.com/soypat/tinyboot/filesystem"
)

// Memory budget.
//
// This is the part of a fuzzing setup that is easy to get catastrophically
// wrong, because nothing about it fails a test — it just eats the machine. Go's
// fuzzer runs GOMAXPROCS workers and drives them as fast as they will go, so any
// per-iteration allocation is multiplied by the core count and by hundreds of
// thousands of iterations per second. A device allocated per iteration is
// gigabytes per second of multi-megabyte garbage, and the resident set wins the
// race against the collector.
//
// So nothing here is allocated per iteration. Every device, every mounted
// filesystem and every scratch buffer lives in a [Harness], harnesses come from
// a free list that is capped rather than garbage collected, and an iteration
// resets what it borrowed instead of building a new one.
//
// The resulting ceiling is the only number that matters, and it is small:
//
//	FAT      2 MiB device x (GOMAXPROCS+2) harnesses
//	littlefs 256 KiB device x (GOMAXPROCS+2) harnesses
//
// On a 16-core machine that is at most 36 MiB of FAT and 4.5 MiB of littlefs,
// held flat for the life of the run. Everything else — the model, the buffers,
// the decoded program — is kilobytes.
const (
	// fatSectors is 4096 because exFAT will not format anything smaller: the fat
	// formatter rejects 2048 sectors and below with FR_MKFS_ABORTED. It is a
	// floor, not a preference.
	fatSectorSize = 512
	fatSectors    = 4096 // 2 MiB, the smallest exFAT that formats.

	// littlefs formats down to 64 KiB, but a device that small fills up in a few
	// operations, and every operation after the device fills is discarded by the
	// oracle. 256 KiB is the size the unit tests use and is a reasonable trade
	// between memory and how deep a program gets before it runs out of room.
	lfsPageSize  = 256
	lfsBlockSize = 4096
	lfsBlocks    = 64 // 256 KiB.
)

// Formatting costs far more than everything an iteration does with the result,
// so it happens once per process and every harness starts from a copy of the
// image. Both are pure functions of nothing, so memoizing them keeps the fuzz
// target deterministic.
var (
	pristineFAT = sync.OnceValue(func() []byte {
		bd := NewRAM(fatSectorSize, fatSectors)
		var fmtr fat.Formatter
		// exFAT because fat's FAT12/16/32 mkfs is not implemented (fat/format.go
		// formatFAT). The flag conversion under test is shared by every variant.
		err := fmtr.Format(bd, fatSectorSize, fatSectors, fat.FormatConfig{Format: fat.FormatExFAT})
		if err != nil {
			panic("fsfuzz: format fat: " + err.Error())
		}
		return bd.mem
	})
	pristineLFS = sync.OnceValue(func() []byte {
		bd := NewRAM(lfsPageSize, lfsBlockSize/lfsPageSize*lfsBlocks)
		var fmtr lfs.Formatter
		err := fmtr.Format(bd, lfsPageSize, lfsBlockSize, lfsBlocks, lfs.FormatConfig{})
		if err != nil {
			panic("fsfuzz: format lfs: " + err.Error())
		}
		return bd.mem
	})
)

// Harness is a mounted filesystem on a reusable RAM device, together with the
// scratch storage one run needs. Get one with [GetFAT] or [GetLittle], run a
// program on it, and hand it back with [Harness.Release]. Do not build one
// yourself: the point of the free list is that the devices are shared.
type Harness struct {
	// Caps describes the backend this harness mounts.
	Caps Caps

	bd    *RAM
	fs    *filesystem.FS
	mount func() error // Re-mounts bd after a Reset.

	pool *harnessPool
	r    runner // Reused across runs, so a run allocates no buffers.
}

// FS is the mounted filesystem, freshly formatted and empty. It is here so that
// a test which is not running a [Program] — one that wants to make half a dozen
// calls by hand — still gets its device from the free list instead of allocating
// one.
func (h *Harness) FS() *filesystem.FS { return h.fs }

// Run executes prog against the harness's filesystem, checking every operation
// against a reference model. It returns nil if the implementation agreed with
// the model throughout, and an error describing the first disagreement
// otherwise.
//
// Call it at most once per [GetFAT] or [GetLittle]: the device is reset when the
// harness is handed out, not here, so a second Run would start from wherever the
// first one left off.
func (h *Harness) Run(prog Program) error {
	return h.r.reset(h.fs, h.Caps, prog).run()
}

// Leaked is the number of file and directory handles the last [Harness.Run] left
// open. It must be zero: a handle returns to its pool in Close and nowhere else,
// so a leaked one is a handle the pool has lost and a backend handle the next
// open has to allocate again. See runner.closeAll, and TestHarnessLeaksNoHandles.
func (h *Harness) Leaked() int { return h.r.leaked() }

// prepare restores the device to its formatted image and remounts it. Resetting
// only the blocks the last run dirtied is what makes this cost nothing.
func (h *Harness) prepare() error {
	h.bd.Reset()
	return h.mount()
}

// Release returns the harness to the free list. Not calling it is not a
// correctness bug — the harness is simply collected, and the next Get allocates
// a fresh one — but doing it in a loop reintroduces exactly the allocation
// churn the free list exists to prevent, so always defer it.
func (h *Harness) Release() { h.pool.put(h) }

// GetFAT returns a harness with a freshly formatted exFAT filesystem mounted.
// Release it when done.
func GetFAT() *Harness { return fatPool.get() }

// GetLittle returns a harness with a freshly formatted littlefs mounted. Release
// it when done.
func GetLittle() *Harness { return lfsPool.get() }

// harnessPool is a free list, deliberately not a [sync.Pool].
//
// A sync.Pool is drained by the garbage collector, which is the right behavior
// for a cache and the wrong one here: under a fuzzer the collector runs
// constantly, so a sync.Pool would hand back a drained pool and reallocate a
// multi-megabyte device on a large fraction of iterations — the exact cost we
// are trying to remove. This free list is never drained, so the devices are
// allocated once and live forever, and its capacity is a hard ceiling on how
// many can exist at all.
type harnessPool struct {
	free chan *Harness
	new  func() *Harness
}

func newHarnessPool(newFn func() *Harness) *harnessPool {
	// GOMAXPROCS+2: one device per fuzz worker, plus slack for a test that holds
	// two at once. A Get beyond the cap still works — it allocates — but the
	// device it allocates is dropped on Release rather than retained, so the
	// ceiling holds no matter how badly a caller misuses this.
	return &harnessPool{
		free: make(chan *Harness, runtime.GOMAXPROCS(0)+2),
		new:  newFn,
	}
}

func (p *harnessPool) get() *Harness {
	var h *Harness
	select {
	case h = <-p.free:
	default:
		h = p.new()
		h.pool = p
	}
	if err := h.prepare(); err != nil {
		// The image was formatted by this package and mounted a moment ago on an
		// identical device, so it mounting is not something a caller can affect
		// or recover from.
		panic("fsfuzz: remount a freshly reset device: " + err.Error())
	}
	return h
}

func (p *harnessPool) put(h *Harness) {
	select {
	case p.free <- h:
	default: // At capacity: drop it, and let the collector have the device.
	}
}

var (
	fatPool = newHarnessPool(func() *Harness {
		bd := newRAMFrom(fatSectorSize, pristineFAT())
		fsys := new(filesystem.FATFS)
		h := &Harness{
			Caps: CapsFAT,
			bd:   bd,
			fs:   filesystem.NewFAT(fsys),
			// Remounting the same FATFS in place is what lets the *filesystem.FS
			// wrapper — and the handle pools inside it — outlive the reset. The
			// wrapper holds this exact pointer, so it keeps working.
			mount: func() error { return fsys.Mount(bd, fatSectorSize, fat.ModeRW) },
		}
		return h
	})

	lfsPool = newHarnessPool(func() *Harness {
		bd := newRAMFrom(lfsPageSize, pristineLFS())
		fsys := new(filesystem.LittleFS)
		h := &Harness{
			Caps:  CapsLittle,
			bd:    bd,
			fs:    filesystem.NewLittle(fsys),
			mount: func() error { return fsys.Mount(bd, lfsPageSize, lfsBlockSize, lfs.ModeRW) },
		}
		return h
	})
)
