package elfutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/soypat/archive/zlib"
	"github.com/soypat/lexorg"
	"github.com/soypat/tinyboot/build/xdwarf"
	"github.com/soypat/tinyboot/build/xelf"
)

var (
	// ErrNoDebugLine reports an ELF carrying no .debug_line section at all.
	ErrNoDebugLine = errors.New("elfutil: ELF has no .debug_line section")
	// ErrNoZlib reports a compressed DWARF section with no inflater to read it.
	// The Go toolchain compresses DWARF by default, so this is the ordinary
	// state of a gc-built binary rather than an exotic one; set
	// [DWARFReaders.Zlib] and load again.
	ErrNoZlib = errors.New("elfutil: DWARF is zlib-compressed, set DWARFReaders.Zlib to a configured *zlib.Reader")
	// ErrNoStreamBuffer reports a compressed .debug_line with no lookback buffer
	// to inflate it through. See [DWARFReaders.Stream] and [StreamBufferFor].
	ErrNoStreamBuffer = errors.New("elfutil: compressed .debug_line needs DWARFReaders.Stream, see StreamBufferFor")
)

// StreamBufferFor returns the smallest [DWARFReaders.Stream] that can serve a
// walk using an aux buffer of aux bytes.
//
// A compressed section is inflated as the decoder walks it rather than held
// whole, and a deflate stream cannot be read backwards. The decoder does step
// back once per unit -- it reads a whole aux worth of header, then starts the
// opcode program at the header's true end -- by at most len(aux). A
// [lexorg.StreamReaderAt] guarantees a lookback of half its buffer, so twice aux
// covers that step with the margin of a full span either side.
func StreamBufferFor(aux int) int { return 2 * aux }

// DWARFReaders holds the per-section state backing an [xdwarf.Sections]. It is
// kept by the caller so one set serves a whole walk, and so its buffers survive
// across binaries: diffing two files reuses everything the first one grew.
type DWARFReaders struct {
	// Zlib inflates SHF_COMPRESSED sections. It must already be configured:
	// this package never configures or allocates one, so how much memory a
	// decompressor gets -- and with it whether any stream can be rejected for
	// want of scratch -- stays the caller's decision. Leaving it nil is fine for
	// an uncompressed binary and reports [ErrNoZlib] for a compressed one, which
	// a caller can treat as "configure one and load again".
	Zlib *zlib.Reader
	// Stream is the lookback buffer a compressed .debug_line is inflated
	// through. It must be at least [StreamBufferFor] the aux the caller will
	// pass to [xdwarf.DecodeLineUnit]; too small and the walk fails partway with
	// a [RewoundError] rather than at the start.
	Stream []byte

	line, lineStr, str dwarfSection
}

// dwarfSection gets at one DWARF section's bytes, in whichever of the three
// forms the section comes in. Only the field matching that form is live.
type dwarfSection struct {
	// rel reads an uncompressed section in place, applying relocations as the
	// bytes come back. Nothing is held resident.
	rel xelf.RelocReaderAt
	// stream inflates a compressed section as the decoder walks forward through
	// it, retaining only enough to cover the decoder's one backward step.
	stream rewindReader
	// buf and mem hold a compressed section that had to be inflated whole:
	// one read at arbitrary offsets, like the string sections where resolving a
	// name is a read wherever that name happens to sit, or one carrying
	// relocations, which are applied by writing into the decompressed bytes.
	buf []byte
	mem bytes.Reader
	// Scratch for relocating an inflated section, kept so a reused DWARFReaders
	// decodes the same relocation table without reallocating.
	relBuf []byte
	syms   []xelf.Sym
}

// LoadDWARF points dst at the DWARF sections of src, and returns the size of
// .debug_line -- the bound a walk over it terminates on.
//
// dst is backed by rr, which must outlive it. Relocations targeting those
// sections are applied, which relocatable objects need since TinyGo emits
// .rel.debug_*. Relocation types this build does not implement leave those
// particular addresses unresolved; the rest of the section is still usable, and
// an unresolved row simply fails to match a symbol.
//
// A compressed .debug_line is inflated as it is walked, so loading it again --
// after growing aux, say -- must go through LoadDWARF again to restart the
// stream.
func LoadDWARF(dst *xdwarf.Sections, rr *DWARFReaders, src *xelf.File) (lineSize int64, err error) {
	*dst = xdwarf.Sections{ByteOrder: src.Header().ByteOrder()}
	for _, tgt := range []struct {
		name string
		sec  *dwarfSection
		dst  *io.ReaderAt
		// seekable marks a section the decoder reads at arbitrary offsets, which
		// a stream cannot serve.
		seekable bool
	}{
		{".debug_line", &rr.line, &dst.Line, false},
		{".debug_line_str", &rr.lineStr, &dst.LineStr, true},
		{".debug_str", &rr.str, &dst.Str, true},
	} {
		fsec, err := src.SectionByName(tgt.name)
		if err != nil {
			continue // Absent; a caller needing it fails when it reaches for it.
		}
		r, size, err := tgt.sec.open(src, fsec, rr, tgt.seekable)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", tgt.name, err)
		}
		*tgt.dst = r
		if !tgt.seekable {
			lineSize = size
		}
	}
	if dst.Line == nil || lineSize <= 0 {
		return 0, ErrNoDebugLine
	}
	return lineSize, nil
}

// open binds one section, decompressing it if it has to.
func (d *dwarfSection) open(src *xelf.File, fsec xelf.FileSection, rr *DWARFReaders, seekable bool) (io.ReaderAt, int64, error) {
	ch, compressed, err := fsec.Compression()
	if err != nil {
		return nil, 0, err
	}
	if !compressed {
		if _, err := d.rel.Reset(src, fsec); err != nil {
			return nil, 0, err
		}
		return &d.rel, fsec.Size(), nil
	}
	if ch.Type != xelf.CompressZLIB {
		return nil, 0, fmt.Errorf("unsupported section compression %d", ch.Type)
	}
	if rr.Zlib == nil {
		return nil, 0, ErrNoZlib
	}
	payload, err := fsec.OpenPayload()
	if err != nil {
		return nil, 0, err
	}
	if err := rr.Zlib.Reset(payload); err != nil {
		return nil, 0, err
	}
	// Relocations address the decompressed bytes and are applied by writing into
	// them, so a section carrying any has to be inflated whole however it is
	// read afterwards. This is the ordinary shape of an object file built with
	// -gz: gcc and clang compress .debug_* in .o output, and the relocations
	// against them stay in .rela.debug_*, since the gABI's only exclusivity rule
	// for SHF_COMPRESSED is against SHF_ALLOC.
	_, relocated := src.RelocationsFor(fsec.Index())
	if seekable || relocated {
		r, size, err := d.inflateWhole(rr.Zlib, ch.Size)
		if err != nil {
			return nil, 0, err
		}
		if relocated {
			if err := d.relocate(src, fsec); err != nil {
				return nil, 0, err
			}
		}
		return r, size, nil
	}
	if len(rr.Stream) == 0 {
		return nil, 0, ErrNoStreamBuffer
	}
	d.stream.Reset(rr.Zlib, rr.Stream)
	return &d.stream, ch.Size, nil
}

// relocate fixes up an already-inflated section, which is how the compressed
// path applies what [xelf.RelocReaderAt] applies as it reads.
func (d *dwarfSection) relocate(src *xelf.File, fsec xelf.FileSection) error {
	rels, ok := src.RelocationsFor(fsec.Index())
	if !ok {
		return nil
	}
	relData, err := rels.AppendData(d.relBuf[:0])
	if err != nil {
		return err
	}
	d.relBuf = relData
	d.syms, err = src.AppendTableSymbols(d.syms[:0])
	if err != nil {
		return err
	}
	// Unhandled relocation types leave their own addresses unresolved without
	// invalidating the rest, the same tolerance RelocReaderAt applies.
	err = xelf.ApplyRelocations(d.buf[:fsec.Size()], relData, d.syms, src.Header())
	if _, partial := err.(xelf.RelocError); err != nil && !partial {
		return err
	}
	return nil
}

// inflateWhole materializes a compressed section, for one that is read at
// arbitrary offsets. The compression header states the decompressed size
// exactly, so the buffer is sized once and only grows to the largest section
// seen.
func (d *dwarfSection) inflateWhole(zr *zlib.Reader, size int64) (io.ReaderAt, int64, error) {
	if int64(cap(d.buf)) < size {
		d.buf = make([]byte, size)
	}
	buf := d.buf[:size]
	if _, err := io.ReadFull(zr, buf); err != nil {
		return nil, 0, err
	}
	// ReadFull stops the moment buf is full, which is before the inflater has
	// seen the stream end -- and so before it has checked the adler32. One more
	// read settles both that and whether the stream outruns the size the
	// compression header promised.
	var tail [1]byte
	switch n, err := zr.Read(tail[:]); {
	case err != nil && err != io.EOF:
		return nil, 0, err
	case n != 0:
		return nil, 0, fmt.Errorf("section inflates past the %d bytes its compression header declares", size)
	}
	d.mem.Reset(buf)
	return &d.mem, size, nil
}

// RewoundError reports a read behind what the inflating reader still holds,
// which means [DWARFReaders.Stream] was too small for the aux in use.
//
// It names the buffer it had but not the one it wanted: the size that would
// have served is [StreamBufferFor] of the caller's aux, and aux is passed to
// [xdwarf.DecodeLineUnit], never to this package. Sizing off the shortfall of
// whichever read happened to fail first would only move the failure to a later
// unit with a smaller header.
type RewoundError struct {
	// Have is the length of the lookback buffer that proved too small.
	Have int
	// Short is how far behind the retained bytes the failing read landed. It is
	// a lower bound on what was missing, not the fix.
	Short int64
}

func (e RewoundError) Error() string {
	return fmt.Sprintf("elfutil: compressed .debug_line read fell %d bytes behind the %d-byte lookback buffer; "+
		"size DWARFReaders.Stream with StreamBufferFor(len(aux))", e.Short, e.Have)
}

func (e RewoundError) Unwrap() error { return lexorg.ErrRewound }

// rewindReader is a [lexorg.StreamReaderAt] that reports a rewind past its
// retained bytes as a [RewoundError]. Bare ErrRewound would surface from the
// middle of a line-table walk naming neither the buffer at fault nor a size to
// fix it with.
type rewindReader struct {
	s lexorg.StreamReaderAt
	n int // Buffer length, for the error.
}

func (r *rewindReader) Reset(src io.Reader, buf []byte) {
	r.s.Reset(src, buf)
	r.n = len(buf)
}

func (r *rewindReader) ReadAt(b []byte, off int64) (int, error) {
	n, err := r.s.ReadAt(b, off)
	if errors.Is(err, lexorg.ErrRewound) {
		start, _ := r.s.Retained()
		return n, RewoundError{Have: r.n, Short: start - off}
	}
	return n, err
}
