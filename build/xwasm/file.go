package xwasm

import (
	"errors"
	"fmt"
	"io"
)

// File is a decoded WebAssembly module: its header and the location of each
// section. Section contents are read on demand through the [io.ReaderAt] given
// to [File.Read], which must outlive the File.
type File struct {
	hdr      Header
	sections []section
	r        io.ReaderAt

	// buf is scratch for decoding section framing and comparing names.
	buf [fileBufSize]byte
}

// section is deliberately just the header: a module may declare thousands of
// tiny custom sections, and nothing per section is worth holding resident but
// where it is.
type section struct {
	SectionHeader
}

// Read parses the module in r, recording where each section lies. It reads the
// header and the framing of each section, never section contents. The module
// is expected to start at offset 0 and end at the end of r.
//
// Calling Read again on the same File reuses its section table, so parsing a
// sequence of modules allocates only when one has more sections than any
// before it.
func (f *File) Read(r io.ReaderAt) error {
	buf := f.buf[:]
	n, err := r.ReadAt(buf[:headerSize], 0)
	if n < headerSize {
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	header, _, err := DecodeHeader(buf)
	if err != nil {
		return err
	}
	sections := f.sections[:0]
	// Leave f describing nothing unless the whole module parses: a half-read
	// section table is worse than none.
	f.hdr, f.sections, f.r = Header{}, sections, nil

	var lastRank uint8
	for off := uint64(headerSize); ; {
		n, err := r.ReadAt(buf[:maxSectionFrame], int64(off))
		if n == 0 {
			if err == io.EOF || err == nil {
				break // Clean end of module on a section boundary.
			}
			return err
		} else if err != nil && err != io.EOF {
			return err
		}
		sh, _, err := DecodeSectionHeader(buf[:n], off)
		if err != nil {
			return err
		}
		if sh.ID != SecCustom {
			rank := sectionRank[sh.ID]
			if rank <= lastRank {
				return makeFormatErr(off, "section out of order or duplicated", sh.ID)
			}
			lastRank = rank
		}
		end := sh.End()
		if end > 1<<63-1 {
			return makeFormatErr(off, errSectionPastEOF.Error(), sh.Size)
		}
		// Probe the last byte: a section claiming more than the file holds is
		// caught here rather than by whichever reader first reaches its tail.
		if n, _ := r.ReadAt(buf[:1], int64(end)-1); n != 1 {
			return makeFormatErr(off, errSectionPastEOF.Error(), sh.Size)
		}
		if len(sections) >= maxSections {
			return makeFormatErr(off, errTooManySecs.Error(), len(sections))
		}
		sections = append(sections, section{SectionHeader: sh})
		off = end
	}
	f.hdr, f.sections, f.r = header, sections, r
	return nil
}

// Header returns the module header.
func (f *File) Header() Header { return f.hdr }

// NumSections returns the number of sections in the module, custom ones
// included.
func (f *File) NumSections() int { return len(f.sections) }

// Section returns the section at sectionIdx, in file order.
func (f *File) Section(sectionIdx int) (FileSection, error) {
	if sectionIdx >= len(f.sections) || sectionIdx < 0 {
		return FileSection{}, errors.New("OOB/negative section index")
	}
	return FileSection{f: f, sindex: sectionIdx}, nil
}

// SectionByID returns the first section with the given id. For any id but
// [SecCustom] that is the only one.
func (f *File) SectionByID(id SectionID) (FileSection, error) {
	for i := range f.sections {
		if f.sections[i].ID == id {
			return FileSection{f: f, sindex: i}, nil
		}
	}
	return FileSection{}, fmt.Errorf("%w: %s", errNoSection, id)
}

// SectionByName returns the first custom section with the given name, or the
// standard section whose id's [SectionID.String] is name ("code", "data", ...).
func (f *File) SectionByName(name string) (FileSection, error) {
	for i := range f.sections {
		s := FileSection{f: f, sindex: i}
		sh := &f.sections[i]
		if sh.ID != SecCustom {
			if sh.ID.String() == name {
				return s, nil
			}
			continue
		}
		ok, err := s.nameEquals(name)
		if err != nil {
			return FileSection{}, err
		} else if ok {
			return s, nil
		}
	}
	return FileSection{}, fmt.Errorf("%w: %q", errNoSection, name)
}

// FileSection is the handle to a module's section.
type FileSection struct {
	f      *File
	sindex int
}

func (fs FileSection) ptr() *section { return &fs.f.sections[fs.sindex] }

// Index returns the index of the section within the module, in file order.
func (fs FileSection) Index() int { return fs.sindex }

// SectionHeader returns the section's header.
func (fs FileSection) SectionHeader() SectionHeader { return fs.ptr().SectionHeader }

// Size returns the size of the section's contents in bytes, which for a custom
// section excludes its name.
func (fs FileSection) Size() int64 { return int64(fs.ptr().Size) }

// Open returns a new [io.SectionReader] reading the section's contents.
func (fs FileSection) Open() *io.SectionReader {
	s := fs.ptr()
	return io.NewSectionReader(fs.f.r, int64(s.Offset), int64(s.Size))
}

// AppendData appends the section's contents to dst and returns the result.
func (fs FileSection) AppendData(dst []byte) ([]byte, error) {
	s := fs.ptr()
	return appendAt(dst, fs.f.r, s.Offset, s.Size)
}

// AppendName appends the section's name to dst: a custom section's own name,
// or for a standard section its id's [SectionID.String].
func (fs FileSection) AppendName(dst []byte) ([]byte, error) {
	s := fs.ptr()
	if s.ID != SecCustom {
		return append(dst, s.ID.String()...), nil
	}
	return appendAt(dst, fs.f.r, s.NameOff, uint64(s.NameLen))
}

// Name returns the section's name. See [FileSection.AppendName].
func (fs FileSection) Name() (string, error) {
	s := fs.ptr()
	if s.ID != SecCustom {
		return s.ID.String(), nil
	}
	b, err := fs.AppendName(nil)
	return string(b), err
}

// nameEquals compares a custom section's name against name, reading it through
// the File's scratch buffer so the comparison allocates nothing.
func (fs FileSection) nameEquals(name string) (bool, error) {
	s := fs.ptr()
	if uint64(s.NameLen) != uint64(len(name)) {
		return false, nil
	}
	buf := fs.f.buf[:]
	for off := 0; off < len(name); {
		chunk := buf[:min(len(buf), len(name)-off)]
		n, err := fs.f.r.ReadAt(chunk, int64(s.NameOff)+int64(off))
		if n < len(chunk) {
			if err == nil || err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return false, err
		}
		if string(chunk) != name[off:off+n] { // Compiles to a comparison, no copy.
			return false, nil
		}
		off += n
	}
	return true, nil
}

func (fs FileSection) String() string {
	if fs.f == nil {
		return "<nil FileSection>"
	}
	name, _ := fs.Name()
	sh := fs.SectionHeader()
	return fmt.Sprintf("%s, %s off=%#x size=%d", name, sh.ID.String(), sh.Offset, sh.Size)
}

// appendAt appends the size bytes at off in r to dst.
func appendAt(dst []byte, r io.ReaderAt, off, size uint64) ([]byte, error) {
	if size == 0 {
		return dst, nil
	}
	if sliceCapWithSize(1, size) < 0 || size > uint64(1<<63-1-len(dst)) {
		return dst, errors.New("section too large")
	}
	dst = slicesGrow(dst, int(size))
	toRead := dst[len(dst) : len(dst)+int(size)]
	n, err := r.ReadAt(toRead, int64(off))
	if n < len(toRead) {
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return dst, err
	}
	return dst[:len(dst)+int(size)], nil
}
