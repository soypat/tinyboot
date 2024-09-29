package xelf

import (
	"bytes"
	"errors"
	"io"
	"math"
)

type File struct {
	hdr      Header
	progs    []prog
	sections []section
	buf      [fileBufSize]byte
}

func (f *File) NumSections() int {
	return int(f.hdr.Shnum)
}

func (f *File) NumProgs() int {
	return int(f.hdr.Phnum)
}

func (f *File) Read(r io.ReaderAt) error {
	buf := f.buf[:]
	if _, err := r.ReadAt(buf[:64], 0); err != nil {
		return err
	}
	header, _, err := DecodeHeader(buf)
	if err != nil {
		return err
	}
	// If the number of sections is greater than or equal to SHN_LORESERVE
	// (0xff00), shnum has the value zero and the actual number of section
	// header table entries is contained in the sh_size field of the section
	// header at index 0.
	bo := header.ByteOrder()
	if header.Shoff > 0 && header.Shnum == 0 {
		println("special initial section")
		n, err := r.ReadAt(buf[:sectionHeaderSize64], int64(header.Shoff))
		if err != nil {
			return makeFormatErr(header.Shoff, err.Error(), n)
		}
		sh, _, err := DecodeSectionHeader(buf[:n], header.Class, bo)
		if err != nil {
			return makeFormatErr(header.Shoff, err.Error(), sh)
		}
		err = sh.Validate(header.Class)
		if err != nil {
			return makeFormatErr(header.Shoff, err.Error(), sh)
		}
		header.Shnum = uint16(sh.FileSize)

		if sh.Type != SecTypeNull {
			return makeFormatErr(header.Shoff, "invalid type of the initial section", sh.Type)
		} else if SectionIndex(header.Shnum) < SecIdxReserveLo {
			return makeFormatErr(header.Shoff, "invalid shnum contained in sh_size", header.Shnum)
		}
		// If the section name string table section index is greater than or
		// equal to SHN_LORESERVE (0xff00), this member has the value
		// SHN_XINDEX (0xffff) and the actual index of the section name
		// string table section is contained in the sh_link field of the
		// section header at index 0.
		if int(header.Shstrndx) == int(SecIdxXindex) {
			if sh.Link > math.MaxUint16 {
				return makeFormatErr(header.Shoff, "initial section link overflows uint16 as shstrndx", sh.Link)
			}
			header.Shstrndx = uint16(sh.Link)
			if header.Shstrndx < uint16(SecIdxReserveLo) {
				return makeFormatErr(header.Shoff, "invalid shstrndx contained in sh_link", header.Shstrndx)
			} else if header.Shstrndx >= header.Shnum {
				return makeFormatErr(header.Shoff, "shstrndx from sh_link in initial section greater than shnum", header.Shstrndx)
			}
		}
	}
	err = header.Validate()
	if err != nil {
		return err
	}

	phentsize := int64(header.Phentsize)
	progHeaderOff := int64(header.Phoff)
	progs := make([]prog, header.Phnum)
	progBuf := buf[:progHeaderSize64]
	if len(progBuf) > int(phentsize) {
		progBuf = progBuf[:phentsize]
	}
	for i := int64(0); i < int64(header.Phnum); i++ {
		progOff := i * phentsize
		fileOff := progHeaderOff + progOff
		n, err := r.ReadAt(progBuf, fileOff)
		if err != nil {
			return err
		}
		ph, _, err := DecodeProgHeader(progBuf[:n], header.Class, bo)
		if err != nil {
			return err
		}
		err = ph.Validate()
		if err != nil {
			return makeFormatErr(uint64(fileOff), err.Error(), ph)
		}
		progs[i] = prog{
			ProgHeader: ph,
			r:          *io.NewSectionReader(r, int64(ph.Off), int64(ph.Filesz)),
		}
	}

	c := sliceCap[section](uint64(header.Shnum))
	if c < 0 {
		return makeFormatErr(0, "too many sections", header.Shnum)
	}
	sections := make([]section, c)
	shentsize := int64(header.Shentsize)
	sectBase := int64(header.Shoff)
	sectBuf := buf[:sectionHeaderSize64]
	if len(sectBuf) > int(shentsize) {
		sectBuf = sectBuf[:shentsize]
	}
	for i := int64(0); i < int64(header.Shnum); i++ {
		sectOff := i * shentsize
		fileOff := sectBase + sectOff
		n, err := r.ReadAt(sectBuf, fileOff)
		if err != nil {
			return err
		}
		sh, _, err := DecodeSectionHeader(sectBuf[:n], header.Class, bo)
		if err != nil {
			return err
		}
		err = sh.Validate(header.Class)
		if err != nil {
			return makeFormatErr(uint64(fileOff), err.Error(), err)
		}
		sections[i] = section{
			SectionHeader: sh,
			sr:            *io.NewSectionReader(r, int64(sh.Offset), int64(sh.FileSize)),
		}
	}
	*f = File{
		hdr:      header,
		progs:    progs,
		sections: sections,
	}
	return nil
}

func (f *File) WriteTo(w io.Writer) (int64, error) {

	return 0, nil
}

func (f *File) Section(sectionIdx int) (FileSection, error) {
	if sectionIdx >= len(f.sections) || sectionIdx < 0 {
		return FileSection{}, errors.New("OOB/negative section index")
	}
	return FileSection{
		f:      f,
		sindex: sectionIdx,
	}, nil
}

func (f *File) SectionByName(name string) (FileSection, error) {
	for i := 0; i < f.NumSections(); i++ {
		s, err := f.Section(i)
		if err != nil {
			return FileSection{}, err
		}
		buf, err := s.AppendName(f.buf[:0])
		if err != nil {
			return FileSection{}, err
		}
		if string(buf) == name {
			return s, nil
		}
	}
	return FileSection{}, errors.New("section not found")
}

// FileSection is the handle to a file's section.
type FileSection struct {
	f      *File
	sindex int
}

func (fs FileSection) ptr() *section {
	return &fs.f.sections[fs.sindex]
}

func (fs FileSection) AppendName(dst []byte) (_ []byte, err error) {
	return fs.f.appendTableStr(dst, int(fs.ptr().Name))
}

func (fs FileSection) Name() (string, error) {
	str, err := fs.AppendName(nil)
	if err != nil {
		return "", err
	}
	return string(str), nil
}

func (fs FileSection) Header() SectionHeader {
	return fs.ptr().SectionHeader
}

func (fs FileSection) Size() int64 {
	return int64(fs.ptr().FileSize) // For now returns uncompressed size.
}

// readAt returns a buffer with fileSection contents with the underlying File's buffer.
func (fs FileSection) readAt(length int, offset int64) ([]byte, error) {
	s := fs.ptr()
	if length > len(fs.f.buf) {
		return nil, errors.New("length larger than file buffer")
	} else if offset >= int64(s.FileSize) {
		return nil, io.EOF
	}
	end := int64(length) + offset
	if end > int64(s.FileSize) {
		// Limit read size to size of section.
		length -= int(end - int64(s.FileSize))
	}

	n, err := s.sr.ReadAt(fs.f.buf[:length], offset)
	if err != nil {
		return nil, err
	}
	return fs.f.buf[:n], nil
}

func (f *File) appendTableStr(dst []byte, start int) ([]byte, error) {
	strndx := int(f.hdr.Shstrndx)
	if strndx == 0 {
		return dst, nil // No string table in ELF.
	}
	shstr, err := f.Section(strndx)
	if err != nil {
		return dst, err
	}
	s := shstr.ptr()
	if s.Type != SecTypeStrTab {
		return dst, makeFormatErr(s.Offset, "strndx points to a non-stringtable section type", s.Type)
	}
	dst, err = shstr.appendStr(dst, start)
	if err != nil {
		return dst, err
	}
	return dst, nil
}

// appendStr extracts a null terminated string from an ELF string table and appends it to dst.
func (fs FileSection) appendStr(dst []byte, start int) ([]byte, error) {
	if start < 0 || int64(start) >= fs.Size() {
		return dst, errors.New("bad section header name value")
	}
	secData, err := fs.readAt(fileBufSize, int64(start))
	if err != nil {
		return dst, err
	}
	strEnd := bytes.IndexByte(secData, 0)
	if strEnd < 0 {
		return dst, errors.New("name too long or bad data")
	}
	return append(dst, secData[:strEnd]...), nil
}
