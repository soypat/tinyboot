package xelf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
)

type File struct {
	hdr      Header
	progs    []prog
	sections []section

	// Below are auxiliary buffers used during data marshalling.

	buf [fileBufSize]byte
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
		header.Shnum = uint16(sh.SizeOnFile)

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
		err = ph.Validate(header.Class)
		if err != nil {
			return makeFormatErr(uint64(fileOff), err.Error(), ph)
		}
		progs[i] = prog{
			ProgHeader: ph,
			sr:         *io.NewSectionReader(r, int64(ph.Off), int64(ph.SizeOnFile)),
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
			sr:            *io.NewSectionReader(r, int64(sh.Offset), int64(sh.SizeOnFile)),
		}
	}
	*f = File{
		hdr:      header,
		progs:    progs,
		sections: sections,
	}
	return nil
}

func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	return n, errors.ErrUnsupported
	b := f.buf[:]
	err = f.hdr.Validate()
	if err != nil {
		return 0, err
	}

	nput, err := f.hdr.Put(b)
	if err != nil {
		return n, err
	}
	nw, err := w.Write(b[:nput])
	n += int64(nw)
	if err != nil {
		return n, err
	} else if nw != nput {
		return n, io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	// We define our ELF layout here.
	phtotsize := int64(f.hdr.Phentsize) * int64(f.hdr.Phnum)
	shtotsize := int64(f.hdr.Shentsize) * int64(f.hdr.Shnum)

	phOff := n
	shOff := phOff + phtotsize
	_ = shtotsize
	_ = shOff
	// And now we consolidate
	bo := f.hdr.ByteOrder()
	for i := range f.progs {
		p := &f.progs[i]
		nput, err = p.ProgHeader.Put(b, f.hdr.Class, bo)
		if err != nil {
			return n, err
		}
		nw, err := w.Write(b[:nput])
		n += int64(nw)
		if err != nil {
			return n, err
		} else if nw != nput {
			return n, io.ErrShortWrite
		}
	}
	for i := range f.sections {
		s := &f.sections[i]
		nput, err = s.SectionHeader.Put(b, f.hdr.Class, bo)
		if err != nil {
			return n, err
		}
		nw, err := w.Write(b[:nput])
		n += int64(nw)
		if err != nil {
			return n, err
		} else if nw != nput {
			return n, io.ErrShortWrite
		}
	}
	return 0, nil
}

func (f *File) Header() Header {
	return f.hdr
}

// Prog returns the program at progIdx index.
func (f *File) Prog(progIdx int) (FileProg, error) {
	if progIdx >= len(f.sections) || progIdx < 0 {
		return FileProg{}, errors.New("OOB/negative prog index")
	}
	return FileProg{
		f:      f,
		pindex: progIdx,
	}, nil
}

// Section returns the section at sectionIdx index.
func (f *File) Section(sectionIdx int) (FileSection, error) {
	if sectionIdx >= len(f.sections) || sectionIdx < 0 {
		return FileSection{}, errors.New("OOB/negative section index")
	}
	return FileSection{
		f:      f,
		sindex: sectionIdx,
	}, nil
}

// SectionByName returns the first section in f with the name.
func (f *File) SectionByName(name string) (FileSection, error) {
	nsect := f.NumSections()
	for i := 0; i < nsect; i++ {
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
	return FileSection{}, errors.New("section by index not found")
}

// SectionByType returns the first section in f with the given type.
func (f *File) SectionByType(typ SectionType) (FileSection, error) {
	nsect := f.NumSections()
	for i := 0; i < nsect; i++ {
		s, err := f.Section(i)
		if err != nil {
			return FileSection{}, err
		}
		if s.ptr().Type == typ {
			return s, nil
		}
	}
	return FileSection{}, errors.New("section by type not found")
}

// FileSection is the handle to a file's section.
type FileSection struct {
	f      *File
	sindex int
}

func (fs FileSection) ptr() *section {
	return &fs.f.sections[fs.sindex]
}

// SectionHeader returns the section's header.
func (fs FileSection) SectionHeader() SectionHeader {
	return fs.ptr().SectionHeader
}

// Size returns the size of the ELF section body after decompression in bytes.
func (fs FileSection) Size() int64 {
	s := fs.ptr()
	if s.Flags&SectionFlag(secFlagCompressed) != 0 {
		return -1 // TODO:calculate uncompressed size.
	}
	return int64(s.SizeOnFile)
}

func (fs FileSection) AppendName(dst []byte) (_ []byte, err error) {
	return fs.f.AppendTableStr(dst, fs.ptr().Name)
}

func (fs FileSection) Name() (string, error) {
	str, err := fs.AppendName(nil)
	if err != nil {
		return "", err
	}
	return string(str), nil
}

// Open returns a new [io.ReadSeeker] reading the ELF section body.
func (fs FileSection) Open() io.ReadSeeker {
	s := fs.ptr()
	if s.Type == SecTypeNobits {
		return io.NewSectionReader(&nobitsSectionReader{}, 0, int64(s.SizeOnFile))
	} else if s.Flags&SectionFlag(secFlagCompressed) != 0 {
		return io.NewSectionReader(&unsupportedCompressionReader{}, 0, int64(s.SizeOnFile))
	}
	return io.NewSectionReader(&s.sr, 0, 1<<63-1)
}

// AppendData appends the section's body to the dst buffer and returns the result.
// AppendData always
func (fs FileSection) AppendData(dst []byte) (_ []byte, err error) {
	s := fs.ptr()
	if s.Type == SecTypeNobits {
		return dst, errReadFromNobits
	} else if s.Flags&SectionFlag(secFlagCompressed) != 0 {
		return dst, errCompressionUnsupported
	}
	sz := fs.Size()
	if sz == 0 {
		return dst, nil
	}
	if sliceCapWithSize(1, uint64(sz)) < 0 || sz+int64(len(dst)) > math.MaxInt {
		return dst, errors.New("section too large")
	}
	dst = slicesGrow(dst, int(sz))
	toRead := dst[len(dst) : len(dst)+int(sz)]

	result, err := fs.readAt(toRead, 0)
	if err != nil {
		return dst, err
	} else if len(result) != len(toRead) {
		return dst, fmt.Errorf("short section read sz=%d sr=%d read=%d", sz, s.sr.Size(), len(result))
	}
	dst = dst[:len(dst)+int(sz)]
	return dst, nil
}

type FileProg struct {
	f      *File
	pindex int
}

func (fp FileProg) ptr() *prog {
	return &fp.f.progs[fp.pindex]
}

// ProgHeader returns the program's header.
func (fp FileProg) ProgHeader() ProgHeader {
	return fp.ptr().ProgHeader
}

// Size returns the size of the ELF program body after decompression in bytes.
func (fp FileProg) Size() int64 {
	return int64(fp.ptr().SizeOnFile) // TODO:calculate uncompressed size.
}

// Open returns a new [io.ReadSeeker] reading the ELF program body.
func (fp FileProg) Open() io.ReadSeeker { return io.NewSectionReader(&fp.ptr().sr, 0, 1<<63-1) }

// readAt returns a buffer with fileSection contents with the underlying File's buffer.
func (fs FileSection) readAt(buf []byte, offset int64) ([]byte, error) {
	s := fs.ptr()
	if s.Type == SecTypeNobits {
		return nil, errReadFromNobits
	}
	return readSRInto(buf, &s.sr, offset)
}

// OfProg returns the prog segment index the section belongs to in memory. OfProg returns error in following cases:
//   - The section occupies no prog memory, which is is true when [SectionHeader.Type] != [SecTypeProgBits].
//   - The section is zero sized.
//   - The section belongs to more than a single prog.
//   - The section is not contained within any of the progs.
func (fs FileSection) OfProg() (progIdx int, err error) {
	sz := fs.Size()
	s := fs.ptr()
	if s.Type != SecTypeProgBits || sz <= 0 {
		return -1, errors.New("section does not correspond to prog memory")
	}

	sAddr := s.Addr
	sEnd := sAddr + uint64(sz)
	nprog := fs.f.NumProgs()
	progIdx = -1
	for i := 0; i < nprog; i++ {
		prog, err := fs.f.Prog(i)
		if err != nil {
			return 0, err
		}
		hdr := prog.ProgHeader()
		pAddr := hdr.Vaddr
		pEnd := hdr.Vaddr + hdr.Memsz

		if aliases(sAddr, sAddr+1, pAddr, pEnd) && aliases(sEnd-1, sEnd, pAddr, pEnd) {
			if progIdx >= 0 {
				return -1, errors.New("section aliases with more than a single prog")
			}
			progIdx = i
		}
	}
	if progIdx < 0 {
		return -1, errors.New("section does not correspond to a prog")
	}
	return progIdx, nil
}

// IsProgAlloc returns true if the section belongs to a prog segment that occupies memory.
func (f FileSection) IsProgAlloc() bool {
	hdr := f.SectionHeader()
	return hdr.Type == SecTypeProgBits && hdr.Flags&SectionFlag(secFlagAlloc) != 0 && hdr.SizeOnFile > 0
}

func (f FileSection) String() string {
	if f.f == nil {
		return "<nil FileSection>"
	}
	name, _ := f.Name()
	hdr := f.SectionHeader()
	return fmt.Sprintf("%s, %s addr=%#x size=%d", name, hdr.Type.String(), hdr.Addr, f.Size())
}

func (f *File) AppendTableStr(dst []byte, start uint32) ([]byte, error) {
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
	dst, err = shstr.appendStr(dst, int(start))
	if err != nil {
		return dst, err
	}
	return dst, nil
}

// appendStr extracts a null terminated string from an ELF string table and appends it to dst.
func (fs FileSection) appendStr(dst []byte, start int) ([]byte, error) {
	if start < 0 {
		return dst, errors.New("bad section header name value")
	} else if int64(start) >= fs.Size() {
		return dst, errors.New("start of string exceeds section size")
	}
	secData, err := fs.readAt(fs.f.buf[:], int64(start))
	if err != nil {
		return dst, err
	}
	strEnd := bytes.IndexByte(secData, 0)
	if strEnd < 0 {
		return dst, errors.New("name too long or bad data")
	}
	return append(dst, secData[:strEnd]...), nil
}

func readSRInto(buf []byte, sr *io.SectionReader, offset int64) ([]byte, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	sz := sr.Size()
	end := int64(len(buf)) + offset
	if offset > sr.Size() {
		return nil, io.EOF
	}
	if end > sz {
		buf = buf[:len(buf)-int(end-sz)]
	}
	n, err := sr.ReadAt(buf, offset)
	if err != nil {
		if err != io.EOF {
			return nil, err
		} else if n == 0 {
			return nil, io.EOF
		} else if n < len(buf) {
			err = io.ErrNoProgress
		}
	}
	return buf[:n], err
}

type nobitsSectionReader struct{}

func (*nobitsSectionReader) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, errReadFromNobits
}

type unsupportedCompressionReader struct{}

func (*unsupportedCompressionReader) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, errCompressionUnsupported
}
