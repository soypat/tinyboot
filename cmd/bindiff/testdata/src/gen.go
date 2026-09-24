package src

//go:generate tinygo build -o "../blinky-a.elf" -target=pca10040 "./a"
//go:generate tinygo build -o "../blinky-b.elf" -target=pca10040 "./b"

// The one WebAssembly fixture, shared with build/xwasm. Every flag after the
// target only shrinks it: the bare wasm-unknown target drops WASI, and the
// rest drop the scheduler, the collector and panic printing. It keeps what the
// tests exercise -- a host import, .rodata and .data segments, the name section
// and DWARF line information -- in about 30 KB, most of it DWARF.
//go:generate tinygo build -o "../../../../testdata/tiny.wasm" -target=wasm-unknown -opt=z -panic=trap -scheduler=none -gc=leaking "./tinywasm"
