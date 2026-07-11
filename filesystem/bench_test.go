package filesystem_test

import (
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/soypat/fat"
	"github.com/soypat/lfs"
	"github.com/soypat/tinyboot/filesystem"
)

// benchFS is one mounted backend presented two ways: through the pooled
// [filesystem.FS], and through [filesystem.FSNoAlloc] with a caller-owned handle.
// Both talk to the same mount, so a benchmark that runs the same operation down
// each path measures exactly what the pooled wrapper costs over the hand-managed
// handle it exists to replace — that difference is the point of the whole design,
// and it is what these benchmarks are here to keep honest.
//
// Numbers across the two backends are NOT comparable: FAT and littlefs are
// mounted on ram devices with the geometry their own tests use (16 MiB of 512 B
// sectors versus 256 KiB of 4 KiB erase blocks), and littlefs is copy-on-write
// where FAT is not. Compare fat against fat, lfs against lfs.
type benchFS struct {
	fs *filesystem.FS

	// openNoAlloc opens path straight through FSNoAlloc into a handle owned by
	// the benchFS, so no pool and no allocation stand between the caller and the
	// backend. The returned handle is only valid when err is nil, and there is
	// exactly one of it: a second open before the first Close reuses the same
	// storage. That is the FSNoAlloc contract, in miniature.
	openNoAlloc func(path string, flag int) (filesystem.FileHandle, error)
}

// eachFS runs fn against a freshly formatted FAT and littlefs filesystem, so
// every benchmark below reports one line per backend.
func eachFS(b *testing.B, fn func(b *testing.B, bfs benchFS)) {
	b.Helper()
	b.Run("fat", func(b *testing.B) {
		fsys := newFATFS(b)
		var h fat.File
		fn(b, benchFS{
			fs: filesystem.NewFAT(fsys),
			openNoAlloc: func(path string, flag int) (filesystem.FileHandle, error) {
				return &h, fsys.OpenFile(&h, path, flag, 0o666)
			},
		})
	})
	b.Run("lfs", func(b *testing.B) {
		fsys := newLittleFS(b)
		var h lfs.File
		fn(b, benchFS{
			fs: filesystem.NewLittle(fsys),
			openNoAlloc: func(path string, flag int) (filesystem.FileHandle, error) {
				return &h, fsys.OpenFile(&h, path, flag, 0o666)
			},
		})
	})
}

// benchWriteFile creates path with n bytes of content, outside the timed region.
func benchWriteFile(b *testing.B, bfs benchFS, path string, n int) {
	b.Helper()
	f, err := bfs.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		b.Fatal("setup create:", err)
	}
	if _, err = f.Write(make([]byte, n)); err != nil {
		b.Fatal("setup write:", err)
	}
	if err = f.Close(); err != nil {
		b.Fatal("setup close:", err)
	}
}

// BenchmarkOpenClose is the headline comparison: the same open-and-close of an
// existing file, once through the pool and once with a caller-owned handle. The
// pooled path should report 0 allocs/op once warm — a nonzero count means a
// handle is escaping the pool on every open — and its ns/op gap over the noalloc
// path is the price of the pool plus the closed-handle guard on [filesystem.File].
func BenchmarkOpenClose(b *testing.B) {
	eachFS(b, func(b *testing.B, bfs benchFS) {
		const path = "/open.txt"
		benchWriteFile(b, bfs, path, 0)

		b.Run("FS", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := bfs.fs.Open(path)
				if err != nil {
					b.Fatal(err)
				}
				if err = f.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("FSNoAlloc", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := bfs.openNoAlloc(path, os.O_RDONLY)
				if err != nil {
					b.Fatal(err)
				}
				if err = f.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// BenchmarkCreateRemove measures the churn a create costs on the metadata: each
// iteration creates a file and removes it again, so the filesystem ends where it
// started and the benchmark can run for any number of iterations without filling
// the device.
func BenchmarkCreateRemove(b *testing.B) {
	eachFS(b, func(b *testing.B, bfs benchFS) {
		const path = "/churn.txt"
		b.ReportAllocs()
		for b.Loop() {
			f, err := bfs.fs.Create(path)
			if err != nil {
				b.Fatal("create:", err)
			}
			if err = f.Close(); err != nil {
				b.Fatal("close:", err)
			}
			if err = bfs.fs.Remove(path); err != nil {
				b.Fatal("remove:", err)
			}
		}
	})
}

// benchSizes are the write and read sizes swept below: one under a FAT sector,
// one at a littlefs erase block, one well past both so the per-call overhead
// stops dominating and the ram device's copy throughput shows through.
var benchSizes = []int{512, 4096, 16384}

// BenchmarkWrite measures sequential write throughput at each size. The file is
// truncated at the start of every iteration by O_TRUNC rather than by a separate
// setup step, so the timed region is exactly one open-write-close cycle: that is
// how a caller actually writes a file, and on littlefs the truncate is not free.
func BenchmarkWrite(b *testing.B) {
	eachFS(b, func(b *testing.B, bfs benchFS) {
		for _, size := range benchSizes {
			b.Run(strconv.Itoa(size), func(b *testing.B) {
				const path = "/write.txt"
				buf := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					f, err := bfs.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
					if err != nil {
						b.Fatal("open:", err)
					}
					if _, err = f.Write(buf); err != nil {
						b.Fatal("write:", err)
					}
					if err = f.Close(); err != nil {
						b.Fatal("close:", err)
					}
				}
			})
		}
	})
}

// BenchmarkRead measures sequential read throughput at each size. The file is
// opened once, outside the loop, and rewound with a Seek per iteration, so this
// isolates the read path from the open path that BenchmarkOpenClose already
// covers.
func BenchmarkRead(b *testing.B) {
	eachFS(b, func(b *testing.B, bfs benchFS) {
		for _, size := range benchSizes {
			b.Run(strconv.Itoa(size), func(b *testing.B) {
				const path = "/read.txt"
				benchWriteFile(b, bfs, path, size)
				f, err := bfs.fs.Open(path)
				if err != nil {
					b.Fatal("open:", err)
				}
				defer f.Close()

				buf := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := f.Seek(0, io.SeekStart); err != nil {
						b.Fatal("seek:", err)
					}
					if _, err := io.ReadFull(f, buf); err != nil {
						b.Fatal("read:", err)
					}
				}
			})
		}
	})
}

// BenchmarkStat measures the one FS operation that cannot avoid allocating: the
// [filesystem.FileInfo] it returns has no Close, so nothing can ever hand it back
// to a pool. Expect 1 alloc/op. It is here so that number stays 1.
func BenchmarkStat(b *testing.B) {
	eachFS(b, func(b *testing.B, bfs benchFS) {
		const path = "/stat.txt"
		benchWriteFile(b, bfs, path, 512)
		b.ReportAllocs()
		for b.Loop() {
			info, err := bfs.fs.Stat(path)
			if err != nil {
				b.Fatal(err)
			}
			if info.Size() != 512 {
				b.Fatalf("size %d, want 512", info.Size())
			}
		}
	})
}

// benchDirEntries is how many files the listing benchmarks put in a directory.
// Kept small: littlefs is mounted on a 256 KiB device, and every entry is
// metadata that has to fit alongside the other benchmarks' files.
const benchDirEntries = 16

// BenchmarkListDir contrasts the two ways to list a directory. ReadNext hands the
// caller an info it keeps, so it must allocate one per entry: expect allocs/op to
// scale with benchDirEntries. ForEachFile lends the callback a single info that
// the backend overwrites in place, so it should report 0 allocs/op no matter how
// many entries there are. That gap is the reason ForEachFile exists, and this is
// the benchmark that proves it did not silently regress into allocating.
func BenchmarkListDir(b *testing.B) {
	eachFS(b, func(b *testing.B, bfs benchFS) {
		const dir = "/list"
		if err := bfs.fs.Mkdir(dir); err != nil {
			b.Fatal("mkdir:", err)
		}
		for i := range benchDirEntries {
			benchWriteFile(b, bfs, dir+"/f"+strconv.Itoa(i), 0)
		}

		// name is the scratch buffer the entry names are appended into. Reusing
		// it is what keeps the ForEachFile path allocation-free: FileInfo.Name
		// would return a fresh string per entry and put the allocations straight
		// back in.
		name := make([]byte, 0, 64)

		b.Run("ReadNext", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				d, err := bfs.fs.OpenDir(dir)
				if err != nil {
					b.Fatal("opendir:", err)
				}
				for {
					info, err := d.ReadNext()
					if err == io.EOF {
						break
					} else if err != nil {
						b.Fatal("readnext:", err)
					}
					name = info.AppendName(name[:0])
				}
				if err = d.Close(); err != nil {
					b.Fatal("close:", err)
				}
			}
		})
		b.Run("ForEachFile", func(b *testing.B) {
			// Hoisted out of the loop on purpose: a closure literal inside it
			// captures name and allocates once per iteration, which would swamp
			// the very number this benchmark exists to report. A caller who wants
			// an allocation-free listing has to hoist it too.
			cb := func(info filesystem.FileInfo) error {
				name = info.AppendName(name[:0])
				return nil
			}
			b.ReportAllocs()
			for b.Loop() {
				d, err := bfs.fs.OpenDir(dir)
				if err != nil {
					b.Fatal("opendir:", err)
				}
				err = d.ForEachFile(cb)
				if err != nil {
					b.Fatal("foreachfile:", err)
				}
				if err = d.Close(); err != nil {
					b.Fatal("close:", err)
				}
			}
		})
	})
}
