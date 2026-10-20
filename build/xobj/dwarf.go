package xobj

import (
	"encoding/binary"
	"io"

	"github.com/soypat/tinyboot/build"
	"github.com/soypat/tinyboot/build/elfutil"
	"github.com/soypat/tinyboot/build/xdwarf"
)

// LoadLines points dst at the binary's DWARF line sections and returns the size
// of .debug_line, the bound a walk over it with [xdwarf.DecodeLineUnit]
// terminates on. Line addresses land in the space [Section.InLines] and
// [Section.LineBase] describe.
//
// An ELF binary's sections may be compressed or need relocating; rr holds the
// state for that, as for [elfutil.LoadDWARF], whose errors -- notably
// [elfutil.ErrNoZlib] -- pass through. A WebAssembly module's DWARF is stored
// plain and needs no rr.
func (f *File) LoadLines(dst *xdwarf.Sections, rr *elfutil.DWARFReaders) (lineSize int64, err error) {
	switch f.format {
	case FormatELF:
		lineSize, err = elfutil.LoadDWARF(dst, rr, &f.elf)
		if err == elfutil.ErrNoDebugLine {
			err = build.ErrNoDebugLine
		}
		return lineSize, err
	case FormatWasm:
		return f.wasmLines(dst)
	}
	return 0, build.ErrNotRead
}

func (f *File) wasmLines(dst *xdwarf.Sections) (int64, error) {
	*dst = xdwarf.Sections{ByteOrder: binary.LittleEndian}
	var lineSize int64
	for i, tgt := range []struct {
		name string
		dst  *io.ReaderAt
	}{
		{".debug_line", &dst.Line},
		{".debug_line_str", &dst.LineStr},
		{".debug_str", &dst.Str},
	} {
		s, err := f.wasm.SectionByName(tgt.name)
		if err != nil {
			continue // Absent; a decoder needing it fails when it reaches for it.
		}
		// Kept in the File so that handing them out allocates nothing.
		f.dwarf[i] = *s.Open()
		*tgt.dst = &f.dwarf[i]
		if i == 0 {
			lineSize = s.Size()
		}
	}
	if dst.Line == nil || lineSize <= 0 {
		return 0, build.ErrNoDebugLine
	}
	return lineSize, nil
}
