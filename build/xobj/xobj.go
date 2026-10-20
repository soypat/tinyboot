// Package xobj reads ELF binaries and WebAssembly modules through one
// format-neutral model: sections, symbols and DWARF line information. Tools
// that only ask where bytes go -- size profilers, symbol listers -- are written
// once against it rather than once per format.
//
// A [File] holds a decoder for each format by value and dispatches on the one
// that read the binary, so it has a size known at compile time and boxes
// nothing. Walking a binary's sections and symbols allocates nothing: every
// window is a fixed array in the File. Names are never read during a walk;
// each has a length query and a read into a buffer the caller sizes from it.
//
// The model covers what both formats share. What only one has -- ELF segments,
// relocations and NOBITS reservations, WebAssembly imports -- is reached through
// [File.ELF] and [File.Wasm].
package xobj

import (
	"io"

	"github.com/soypat/tinyboot/build"
	"github.com/soypat/tinyboot/build/xelf"
	"github.com/soypat/tinyboot/build/xwasm"
)

// Format identifies the container a [File] read.
type Format uint8

const (
	FormatNone Format = iota // none
	FormatELF                // elf
	FormatWasm               // wasm
)

func (f Format) String() string {
	switch f {
	case FormatELF:
		return "elf"
	case FormatWasm:
		return "wasm"
	}
	return "none"
}

// sniff tells the formats apart by their magic, read through f's scratch.
func (f *File) sniff(r io.ReaderAt) (Format, error) {
	magic := f.scratch[:4]
	if n, _ := r.ReadAt(magic, 0); n != len(magic) {
		return FormatNone, build.ErrUnknownFormat
	}
	switch string(magic) {
	case "\x7fELF":
		return FormatELF, nil
	case "\x00asm":
		return FormatWasm, nil
	}
	return FormatNone, build.ErrUnknownFormat
}

// HeaderCounts returns how many section and program headers the binary in r
// has, reading no more than its framing: the sizes of the tables [File.Read]
// keeps. A caller holding its memory to a bound counts first and decides
// whether to go on. A WebAssembly module has no program headers. What f
// describes is untouched.
func (f *File) HeaderCounts(r io.ReaderAt) (sections, progs int, err error) {
	format, err := f.sniff(r)
	if err != nil {
		return 0, 0, err
	}
	if format == FormatWasm {
		sections, err = f.wasm.CountSections(r)
		return sections, 0, err
	}
	h, err := f.elf.ReadHeader(r)
	return int(h.Shnum), int(h.Phnum), err
}

// windowSize is the size of each streaming reader's window. Larger windows
// mean fewer reads; anything past a few ELF symbols or WebAssembly framings
// works.
const windowSize = 512

// File is an ELF binary or a WebAssembly module, whichever [File.Read] found.
// Section contents are read on demand through the [io.ReaderAt] given to Read,
// which must outlive the File.
//
// A File is reusable: Read again to describe another binary, keeping its
// tables. Walks share the File's readers, so only one runs at a time.
type File struct {
	format Format
	elf    xelf.File
	wasm   xwasm.File

	syms  xelf.SymReader
	code  xwasm.CodeReader
	data  xwasm.DataReader
	names xwasm.NameReader
	// win holds a window for each streaming reader that can be live at once:
	// symbols or code, data, and names.
	win [3][windowSize]byte
	// scratch holds a binary's magic, and the part of a section name
	// classification looks at.
	scratch [32]byte
	// dwarf backs the readers LoadLines hands out for a WebAssembly module.
	dwarf [3]io.SectionReader
	err   error
}

// Read parses the binary in r, which must start at offset 0: an ELF binary or
// a WebAssembly module, told apart by their magic. Only headers are read;
// contents are read when walked. On error f describes no binary.
//
// Read allocates only to grow its decoder's tables for a binary with more
// headers than any it read before; see [File.HeaderCounts].
func (f *File) Read(r io.ReaderAt) error {
	f.format, f.err = FormatNone, nil
	format, err := f.sniff(r)
	if err != nil {
		return err
	}
	switch format {
	case FormatELF:
		err = f.elf.Read(r)
	case FormatWasm:
		err = f.wasm.Read(r)
	}
	if err != nil {
		return err
	}
	f.format = format
	return nil
}

// Format reports which container f read, or [FormatNone].
func (f *File) Format() Format { return f.format }

// ELF returns the ELF decoder when f read an ELF binary, for what the
// format-neutral model leaves out: segments, relocations, NOBITS sections.
func (f *File) ELF() (*xelf.File, bool) { return &f.elf, f.format == FormatELF }

// Wasm returns the WebAssembly decoder when f read a module, for what the
// format-neutral model leaves out: imports, globals, custom sections' contents.
func (f *File) Wasm() (*xwasm.File, bool) { return &f.wasm, f.format == FormatWasm }

// Err returns why the last [File.Sections] or [File.Symbols] walk stopped
// early, or nil if it ran to completion or the caller stopped it.
func (f *File) Err() error { return f.err }
