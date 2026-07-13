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

The block device is also **sparse**, which is what makes FAT32 testable at all. FAT32 is *defined* as having more than 65525 clusters, so the smallest volume a driver will mount as FAT32 — rather than silently as FAT16 — is 32.5 MiB. Storing only the blocks something has actually written brings a formatted one down to 869 KiB.

```sh
go test ./filesystem/...                                          # deterministic: seeded programs + corpus-stability golden

# One target per backend: go test -fuzz runs one at a time. Corpus files are
# interchangeable between them, so a find from one is worth copying to the others.
GOMEMLIMIT=256MiB go test -run=^$ -fuzz=FuzzFAT32  -fuzztime=60s ./filesystem/
GOMEMLIMIT=256MiB go test -run=^$ -fuzz=FuzzExFAT  -fuzztime=60s ./filesystem/
GOMEMLIMIT=256MiB go test -run=^$ -fuzz=FuzzLittle -fuzztime=60s ./filesystem/
```

### Deviations from POSIX the fuzzer found
The fuzzer found these. In every row exactly one backend also disagreed with `os.File`, which is what made them bugs rather than taste. All but one are now fixed upstream in `fat`/`lfs`; the model enforces the correct behavior on every operation, and [`conformance_test.go`](./filesystem/conformance_test.go) pins each fix with an `os.File` arm as the referee.

FAT32 and exFAT share a driver above the FAT itself, and every bug below reproduced identically on both — the evidence that they lived in the file layer rather than in one variant's allocator.

| Behavior | POSIX (`os.File`) | Was broken in | Status |
|---|---|---|---|
| `Read`/`ReadAt` on an `O_WRONLY` handle | `EBADF` | `lfs` returned the data | **fixed** in `lfs` |
| `Seek` past EOF on a writable handle | offset moves, file unchanged | `fat` grew the file | **fixed**: virtual offset in `fat` |
| `Seek` past EOF on a read-only handle | offset moves there | `fat` clipped to EOF, reported success | **fixed**: virtual offset in `fat` |
| `Truncate` while the offset is past the new size | offset unchanged | `fat` moved it to the new size | **fixed** in `fat` |
| Reading a hole (grown over, never written) | zeros | `fat` returned raw media contents | **fixed**: zero-fill by default, `fat.FSConfig{NoZeroFilling}` opts out |
| `Read` on a fresh `O_RDONLY｜O_APPEND` handle | reads from 0 | `fat` opened the handle at EOF | **fixed**: `fat.ModeAppend` is per-write POSIX append |
| `O_APPEND` write position | EOF before every write | `fat`: EOF once at open, a later `Seek` stuck | **fixed** in `fat`; `lfs` remains **forward-only** (`Caps.AppendForwardOnly`) |
| Name case | case-sensitive | — | FAT is case-insensitive by design (`Caps.CaseInsensitive`) |

The last two rows carry the remaining `Caps` flags: real capability differences, modelled rather than quarantined. littlefs's append matches C littlefs (`lfs_file_write` only moves the position *forward* to EOF, never back), and diverging from the reference implementation for that corner is not worth it.

The hole bug was the one that mattered. FatFs grows a file by allocating clusters and never erasing them, so a hole returned whatever the flash last held — on a part that has ever deleted a file, that is the deleted file's contents, handed to a caller who never wrote them and was never given them. This is deliberate FatFs policy (the zeroing primitive exists and is used for directory clusters only), so `fat` now zero-fills by default and keeps the FatFs behavior behind `FSConfig{NoZeroFilling: true}` for byte-exact compatibility.

The `O_APPEND` read bug is a good advertisement for the method: it needs a five-operation program — create with `O_APPEND`, write, close, reopen `O_RDONLY|O_APPEND`, read — and nobody sits down to write that test. POSIX says `O_APPEND` governs writes only; the old open-time seek moved the *read* offset too, and the file came back empty when it was not.
