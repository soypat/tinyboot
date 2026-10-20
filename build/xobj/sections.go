package xobj

import (
	"bytes"
	"io"

	"github.com/soypat/tinyboot/build"
	"github.com/soypat/tinyboot/build/xelf"
	"github.com/soypat/tinyboot/build/xwasm"
)

// Class is what a section holds, in terms both formats share.
type Class uint8

const (
	ClassMeta  Class = iota // meta: anything else, from symbol tables to custom sections.
	ClassCode               // code: machine code or WebAssembly function bodies.
	ClassData               // data: initialized data loaded at run time.
	ClassBSS                // bss: zero-initialized data occupying no file bytes.
	ClassDebug              // debug: DWARF.
)

func (c Class) String() string {
	switch c {
	case ClassCode:
		return "code"
	case ClassData:
		return "data"
	case ClassBSS:
		return "bss"
	case ClassDebug:
		return "debug"
	}
	return "meta"
}

// Section is one section of a binary, in either format. Its name is read on
// request: [File.SectionNameLen] sizes a buffer, [File.ReadSectionName] fills
// it.
type Section struct {
	// Index is the section's index in the binary, which [Symbol.Section]
	// refers to: its ELF section header index, or its position in a WebAssembly
	// module.
	Index int
	Class Class
	// Off and Size locate the section's contents in the file. Size is the bytes
	// the contents occupy there: zero for a NOBITS section.
	Off, Size uint64
	// Loaded marks a section occupying memory at run time, MemSize bytes at Addr.
	// No WebAssembly section is: linear memory is laid out at instantiation.
	Loaded        bool
	Addr, MemSize uint64
	// InLines marks a section whose bytes the DWARF line table describes, at
	// address LineBase plus their offset in the section. An ELF binary has one
	// address space, the load addresses. A WebAssembly module's line table
	// describes only the Code section, by offset.
	InLines  bool
	LineBase uint64
}

// sectionFlag values xelf keeps unexported.
const (
	elfFlagAlloc     xelf.SectionFlag = 0x2 // SHF_ALLOC
	elfFlagExecInstr xelf.SectionFlag = 0x4 // SHF_EXECINSTR
)

// NumSections returns the number of entries in the binary's section table. In
// an ELF binary that counts the null section at index 0, which
// [File.Sections] leaves out.
func (f *File) NumSections() int {
	switch f.format {
	case FormatELF:
		return f.elf.NumSections()
	case FormatWasm:
		return f.wasm.NumSections()
	}
	return 0
}

// HeaderBytes returns the bytes the binary spends on structure rather than
// section contents: for ELF the file header and both header tables, for
// WebAssembly the preamble and each section's id, size and name framing.
// Whatever a binary's sections and headers leave of its size is padding.
func (f *File) HeaderBytes() int64 {
	switch f.format {
	case FormatELF:
		h := f.elf.Header()
		return int64(h.HeaderSize()) + int64(h.Phentsize)*int64(h.Phnum) + int64(h.Shentsize)*int64(h.Shnum)
	case FormatWasm:
		n := int64(f.wasm.Header().HeaderSize())
		for i := 0; i < f.wasm.NumSections(); i++ {
			s, _ := f.wasm.Section(i)
			n += int64(s.SectionHeader().FrameSize())
		}
		return n
	}
	return 0
}

// Sections yields each of the binary's sections in index order. ELF's null
// sections are left out. [File.Err] reports why a walk stopped early.
func (f *File) Sections(yield func(Section) bool) {
	f.err = nil
	switch f.format {
	case FormatELF:
		f.err = f.elfSections(yield)
	case FormatWasm:
		f.err = f.wasmSections(yield)
	default:
		f.err = build.ErrNotRead
	}
}

func (f *File) elfSections(yield func(Section) bool) error {
	for i := 0; i < f.elf.NumSections(); i++ {
		s, err := f.elf.Section(i)
		if err != nil {
			return err
		}
		sh := s.SectionHeader()
		if sh.Type == xelf.SecTypeNull {
			continue
		}
		sec := Section{
			Index:    i,
			Off:      sh.Offset,
			Size:     sh.SizeOnFile,
			Loaded:   sh.Flags&elfFlagAlloc != 0,
			Addr:     sh.Addr,
			LineBase: sh.Addr,
		}
		if sec.Loaded {
			sec.MemSize, sec.InLines = sh.SizeOnFile, true
		}
		debug, err := isDebug(f.scratch[:], s)
		if err != nil {
			return err
		}
		switch {
		case sh.Type == xelf.SecTypeNobits:
			sec.Size, sec.Class = 0, ClassBSS
		case debug:
			sec.Class = ClassDebug
		case sh.Flags&elfFlagExecInstr != 0:
			sec.Class = ClassCode
		case sec.Loaded:
			sec.Class = ClassData
		}
		if !yield(sec) {
			return nil
		}
	}
	return nil
}

func (f *File) wasmSections(yield func(Section) bool) error {
	for i := 0; i < f.wasm.NumSections(); i++ {
		s, err := f.wasm.Section(i)
		if err != nil {
			return err
		}
		sh := s.SectionHeader()
		sec := Section{Index: i, Off: sh.Offset, Size: sh.Size}
		switch sh.ID {
		case xwasm.SecCode:
			sec.Class, sec.InLines = ClassCode, true
		case xwasm.SecData:
			sec.Class = ClassData
		case xwasm.SecCustom:
			debug, err := isDebug(f.scratch[:], s)
			if err != nil {
				return err
			} else if debug {
				sec.Class = ClassDebug
			}
		}
		if !yield(sec) {
			return nil
		}
	}
	return nil
}

// isDebug reports whether s is named as a DWARF section, compressed GNU-style
// or not, reading its name through scratch. A name too long for scratch is no
// DWARF section's.
func isDebug[S section](scratch []byte, s S) (bool, error) {
	n, err := s.ReadName(scratch)
	if err == io.ErrShortBuffer {
		return false, nil
	} else if err != nil {
		return false, err
	}
	name := scratch[:n]
	return bytes.HasPrefix(name, []byte(".debug_")) || bytes.HasPrefix(name, []byte(".zdebug_")), nil
}

// section is the method set [xelf.FileSection] and [xwasm.FileSection] share,
// signature for signature.
type section interface {
	Index() int
	Size() int64
	Open() *io.SectionReader
	NameLen() (int, error)
	ReadName(dst []byte) (int, error)
	NameEquals(name string) bool
	AppendName(dst []byte) ([]byte, error)
	AppendData(dst []byte) ([]byte, error)
}

// object is the method set [xelf.File] and [xwasm.File] share, over their own
// section types. The helpers below are written once against it.
type object[S section] interface {
	NumSections() int
	Section(i int) (S, error)
	SectionByName(name string) (S, error)
}

var (
	_ object[xelf.FileSection]  = (*xelf.File)(nil)
	_ object[xwasm.FileSection] = (*xwasm.File)(nil)
)

// SectionIndex returns the index of the first section named name.
func (f *File) SectionIndex(name string) (int, error) {
	switch f.format {
	case FormatELF:
		return sectionIndex(&f.elf, name)
	case FormatWasm:
		return sectionIndex(&f.wasm, name)
	}
	return -1, build.ErrNotRead
}

// SectionNameLen returns the length of the name of the section at index i. A
// standard WebAssembly section is named after its id: "code", "data".
func (f *File) SectionNameLen(i int) (int, error) {
	switch f.format {
	case FormatELF:
		return sectionNameLen(&f.elf, i)
	case FormatWasm:
		return sectionNameLen(&f.wasm, i)
	}
	return 0, build.ErrNotRead
}

// ReadSectionName reads the name of the section at index i into dst, which
// [File.SectionNameLen] sizes, and returns its length. A dst too short for the
// name fails with [io.ErrShortBuffer].
func (f *File) ReadSectionName(dst []byte, i int) (int, error) {
	switch f.format {
	case FormatELF:
		return readSectionName(&f.elf, dst, i)
	case FormatWasm:
		return readSectionName(&f.wasm, dst, i)
	}
	return 0, build.ErrNotRead
}

// AppendSectionData appends the contents of the section at index i to dst.
func (f *File) AppendSectionData(dst []byte, i int) ([]byte, error) {
	switch f.format {
	case FormatELF:
		return appendSectionData(&f.elf, dst, i)
	case FormatWasm:
		return appendSectionData(&f.wasm, dst, i)
	}
	return dst, build.ErrNotRead
}

func sectionIndex[S section, O object[S]](o O, name string) (int, error) {
	s, err := o.SectionByName(name)
	if err != nil {
		return -1, err
	}
	return s.Index(), nil
}

func sectionNameLen[S section, O object[S]](o O, i int) (int, error) {
	s, err := o.Section(i)
	if err != nil {
		return 0, err
	}
	return s.NameLen()
}

func readSectionName[S section, O object[S]](o O, dst []byte, i int) (int, error) {
	s, err := o.Section(i)
	if err != nil {
		return 0, err
	}
	return s.ReadName(dst)
}

func appendSectionData[S section, O object[S]](o O, dst []byte, i int) ([]byte, error) {
	s, err := o.Section(i)
	if err != nil {
		return dst, err
	}
	return s.AppendData(dst)
}
