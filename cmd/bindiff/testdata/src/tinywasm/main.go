// Package main is the WebAssembly test fixture: small, but with a host
// import, read-only and writable data, and DWARF line information.
package main

import "unsafe"

//go:wasmimport env emit
func emit(ptr unsafe.Pointer, n uint32)

var greetings = [...]string{"hello", "hola", "ciao"} // .rodata

var counter uint32 = 7 // .data

func add(a, b uint32) uint32 { return a + b }

func main() {}

// run is exported rather than left to main: the bare wasm-unknown target builds
// a library, whose main is never called and would be dropped.
//
//go:wasmexport run
func run() {
	counter = add(counter, 1)
	s := greetings[counter%uint32(len(greetings))]
	emit(unsafe.Pointer(unsafe.StringData(s)), uint32(len(s)))
}
