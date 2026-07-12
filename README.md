# tinyboot
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/tinyboot)](https://pkg.go.dev/github.com/soypat/tinyboot)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/tinyboot)](https://goreportcard.com/report/github.com/soypat/tinyboot)
[![codecov](https://codecov.io/gh/soypat/tinyboot/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/tinyboot)
[![Go](https://github.com/soypat/tinyboot/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/tinyboot/actions/workflows/go.yml)

Tools for working with program builds and bootable partitions.

How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/tinyboot@latest
```

## Package layout
There are two main top level packages:
- [`boot`](./boot): Concerns storage formats for booting a computer such as MBT, GPT and Raspberry Pi's picobin format.
    - [`boot/mbr`](./boot/mbr): Master Boot Record Partition Table interfacing.
    - [`boot/gpt`](./boot/gpt): GUID Partition Table interfacing.
    - [`boot/picobin`](./boot/picobin): Raspberry Pi's bootable format for RP2350 and RP2040.

- [`build`](./build): Concerns manipulation of computer program formats such as ELF and UF2.
    - [`build/elfutil`](./build/elfutil): Manipulation of ELF files that works on top of `debug/elf` standard library package.
    - [`build/uf2`](./build/uf2): Manipulation of Microsoft's UF2 format

- [`filesystem`](./filesystem): Portable `io/fs`-like API over embedded filesystems (FAT12/16/32 and exFAT via [`soypat/fat`](https://github.com/soypat/fat), littlefs via [`soypat/lfs`](https://github.com/soypat/lfs)).
    - [`filesystem/fsfuzz`](./filesystem/fsfuzz): Differential fuzzing and conformance kit for filesystem implementations.

## picobin tool
picobin tool permits users to inspect RP2350 and RP2040 binaries which are structured according to Raspberry Pi's picobin format.

## Fuzz testing filesystems
`filesystem/fsfuzz` fuzzes a filesystem by running it against an in-memory reference model and comparing every result. Randomness is kept out of the fuzz target:

```
random bytes ──Decode──► Program ──Run──► real FS + reference model
                (only entropy         (deterministic, consumes
                 consumer)             no input, all the checks)
```

`Decode` turns the fuzzer's bytes into a typed list of filesystem operations, and it is the only code that ever looks at those bytes. `Run` executes the program and asserts the invariants. Because `Run` consumes no input, **adding a new oracle can never invalidate the corpus** — an old regression file still decodes to exactly the program it decoded to when it was recorded. A target that instead pulls entropy as it goes (`consumeByte()` style) rots its whole corpus the moment anyone inserts a read.

Corpus stability is a hard contract, enforced by a golden test:
- Records are **fixed-width, 8 bytes**. A byte's meaning is fixed per (opcode, position).
- The opcode table has **64 slots and never changes size**; entries are never reordered or removed. A new operation fills a reserved slot, so every *other* record in every existing corpus file keeps its meaning.
- Nothing reachable from `Decode` or `Run` may use `rand`, `time`, map iteration or goroutines. Random program generation lives in `gen.go`, which produces corpus *bytes* offline — an artifact, never a decision made at run time.

8-byte alignment also buys good repros: Go's minimizer deletes byte ranges, so shrinking a failure drops whole operations and `Program.String()` prints a readable trace.

Memory is bounded on purpose, because a fuzzer that allocates per iteration will kill the machine it runs on long before it finds a bug. Devices and mounted filesystems come from a capped free list (not `sync.Pool`, which the GC drains and so reintroduces the exact churn under a fuzzer); a device resets by restoring only the blocks the program dirtied; and every handle is closed and the count asserted, since a handle that escapes its pool is a handle the pool has lost forever. An iteration costs ~2.6 KiB and 14 allocations, guarded by `BenchmarkFuzzIteration`.

The block device is also **sparse**, which is what makes FAT32 testable at all. FAT32 is *defined* as having more than 65525 clusters, so the smallest volume a driver will mount as FAT32 — rather than silently as FAT16 — is over 32 MiB. Storing only the blocks something has actually written brings a formatted 32.5 MiB volume down to 859 KiB.

```sh
go test ./filesystem/...                                          # deterministic: seeded programs + corpus-stability golden

# One target per backend: go test -fuzz runs one at a time. Corpus files are
# interchangeable between them, so a find from one is worth copying to the others.
GOMEMLIMIT=256MiB go test -run=^$ -fuzz=FuzzFAT32  -fuzztime=60s ./filesystem/
GOMEMLIMIT=256MiB go test -run=^$ -fuzz=FuzzExFAT  -fuzztime=60s ./filesystem/
GOMEMLIMIT=256MiB go test -run=^$ -fuzz=FuzzLittle -fuzztime=60s ./filesystem/
```

### Known deviations from POSIX
The fuzzer found these. In every row exactly one backend also disagrees with `os.File`, which is what makes them bugs rather than taste. They are quarantined behind `fsfuzz.Caps` flags and pinned by tests in [`divergence_test.go`](./filesystem/divergence_test.go) that assert the *wrong* behavior on purpose — fix one upstream and its test fails, which is the signal to delete the flag and the test together. A quarantine flag that outlives its bug is how a fuzzer goes quietly blind.

FAT32 and exFAT share a driver above the FAT itself, and every bug below reproduces identically on both — which is the evidence that they live in the file layer rather than in one variant's allocator.

| Behavior | POSIX (`os.File`) | FAT32 / exFAT (`fat`) | littlefs (`lfs`) | `Caps` flag |
|---|---|---|---|---|
| `Read`/`ReadAt` on an `O_WRONLY` handle | `EBADF` | denied | **returns the data** | `ReadIgnoresAccessMode` |
| `Seek` past EOF on a writable handle | offset moves, file unchanged | **grows the file** | offset moves, file unchanged | `SeekBoundedBySize` |
| `Seek` past EOF on a read-only handle | offset moves there | **clips to EOF, reports success** | offset moves there | `SeekBoundedBySize` |
| `Truncate` while the offset is past the new size | offset unchanged | **offset moves to the new size** | offset unchanged | `TruncateMovesOffset` |
| Reading a hole (grown over, never written) | zeros | **raw media contents** | zeros | `HolesAreGarbage` |
| `Read` on a fresh `O_RDONLY｜O_APPEND` handle | reads from 0 | **EOF: the handle opens at EOF** | reads from 0 | `AppendPerWrite` |
| `O_APPEND` write position | EOF before every write | **EOF once, at open — a later `Seek` sticks** | EOF before every write, but only moves *forward* | `AppendPerWrite` |
| Name case | case-sensitive | **case-insensitive** (casefolds) | case-sensitive | `CaseInsensitive` |

The last row is a real capability difference and is modelled rather than quarantined. The rest are bugs.

`HolesAreGarbage` is the one that matters. FatFs grows a file by allocating clusters and never erasing them, so a hole returns whatever the flash last held — on a part that has ever deleted a file, that is the deleted file's contents, handed to a caller who never wrote them and was never given them.

The `O_APPEND` read bug is a good advertisement for the method: it needs a five-operation program — create with `O_APPEND`, write, close, reopen `O_RDONLY|O_APPEND`, read — and nobody sits down to write that test. FAT has no native append this package can use, so it emulates one by seeking to the end at open, and that seek moves the *read* offset too. POSIX says `O_APPEND` governs writes only. The file comes back empty, and it is not empty.
