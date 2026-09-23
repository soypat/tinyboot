package src

//go:generate tinygo build -o "../blinky-a.elf" -target=pca10040 "./a
//go:generate tinygo build -o "../blinky-b.elf" -target=pca10040 "./b

// WebAssembly fixtures, shared with build/xwasm. One carries DWARF and one is
// built without it, leaving only the name section.
//go:generate tinygo build -o "../../../../testdata/hello.wasm" -target=wasip1 "./hellowasm"
//go:generate tinygo build -o "../../../../testdata/hello-nodebug.wasm" -target=wasip1 -no-debug "./hellowasm"
