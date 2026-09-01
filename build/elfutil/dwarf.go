package elfutil

import (
	"errors"
	"io"

	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xelf"
)

// DWARFReaders holds the per-section readers that back an [xdwarf.Sections].
// They are kept by the caller so one set can serve a whole walk, and so the
// relocation tables they decode are reused rather than rebuilt per section.
type DWARFReaders struct {
	Line, LineStr, Str xelf.RelocReaderAt
}

// LoadDWARF points dst at the DWARF sections of src, and returns the size of
// .debug_line -- the bound a walk over it terminates on.
//
// The sections are addressed, not loaded: dst is backed by the readers in rr,
// which must outlive it. Relocations targeting those sections are applied as the
// bytes are read, which relocatable objects need -- TinyGo emits .rel.debug_*.
// Relocation types this build does not implement leave those particular
// addresses unresolved; the rest of the section is still usable, and unresolved
// rows simply fail to match a symbol.
func LoadDWARF(dst *xdwarf.Sections, rr *DWARFReaders, src *xelf.File) (lineSize int64, err error) {
	hdr := src.Header()
	*dst = xdwarf.Sections{ByteOrder: hdr.ByteOrder()}
	for _, tgt := range []struct {
		name string
		rr   *xelf.RelocReaderAt
		dst  *io.ReaderAt
		size *int64
	}{
		{".debug_line", &rr.Line, &dst.Line, &lineSize},
		{".debug_line_str", &rr.LineStr, &dst.LineStr, nil},
		{".debug_str", &rr.Str, &dst.Str, nil},
	} {
		fsec, err := src.SectionByName(tgt.name)
		if err != nil {
			continue
		}
		if _, err := tgt.rr.Reset(src, fsec); err != nil {
			return 0, err
		}
		*tgt.dst = tgt.rr
		if tgt.size != nil {
			*tgt.size = fsec.Size()
		}
	}
	if dst.Line == nil || lineSize <= 0 {
		return 0, errors.New("ELF missing .debug_line section")
	}
	return lineSize, nil
}
