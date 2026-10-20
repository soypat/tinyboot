package xelf

import (
	"bytes"
	"fmt"
	"io"
	"math"

	"github.com/soypat/tinyboot/build"
)

type File struct {
	hdr      Header
	progs    []prog
	sections []section

	// Below are auxiliary buffers used during data marshalling.

	buf [fileBufSize]byte
	// strbuf is the fill buffer for reading string-table entries. It is separate
	// from buf because a caller may pass buf itself as the destination to append
	// a name into, and a name spanning more than one read would otherwise have
	// its own bytes overwritten by the next fill.
	strbuf [fileBufSize]byte
}

// NumSections returns the number of sections in the ELF binary as specified by the ELF header.
func (f *File) NumSections() int {
	return int(f.hdr.Shnum)
}

// NumProgs returns the number of prog segments in the ELF binary as specified by the ELF header.
func (f *File) NumProgs() int {
	return int(f.hdr.Phnum)
}

// ReadHeader reads and validates the ELF header of the binary in r through
// f's scratch, leaving what f describes untouched. For a binary with more
// sections than the header's fields can count, it resolves the true count and
// string table index from the initial section header.
//
// The header's Shnum and Phnum are the sizes of the tables [File.Read] keeps,
// so a caller holding its memory to a bound reads the header first and decides
// whether to go on.
func (f *File) ReadHeader(r io.ReaderAt) (Header, error) {
	return readHeader(r, f.buf[:])
}

// readHeader is ReadHeader through buf, which must hold an ELF64 header.
func readHeader(r io.ReaderAt, buf []byte) (Header, error) {
	if _, err := r.ReadAt(buf[:headerSize64], 0); err != nil {
		return Header{}, err
	}
	header, _, err := DecodeHeader(buf)
	if err != nil {
		return Header{}, err
	}
	// If the number of sections is greater than or equal to SHN_LORESERVE
	// (0xff00), shnum has the value zero and the actual number of section
	// header table entries is contained in the sh_size field of the section
	// header at index 0.
	if header.Shoff > 0 && header.Shnum == 0 {
		n, err := r.ReadAt(buf[:sectionHeaderSize64], int64(header.Shoff))
		if err != nil {
			return Header{}, err
		}
		sh, _, err := DecodeSectionHeader(buf[:n], header.Class, header.ByteOrder())
		if err != nil {
			return Header{}, err
		} else if err = sh.Validate(header.Class); err != nil {
			return Header{}, err
		}
		header.Shnum = uint16(sh.SizeOnFile)
		if sh.Type != SecTypeNull {
			return Header{}, build.ErrBadInitialSection
		} else if SectionIndex(header.Shnum) < SecIdxReserveLo {
			return Header{}, build.ErrBadExtendedShnum
		}
		// If the section name string table section index is greater than or
		// equal to SHN_LORESERVE (0xff00), this member has the value
		// SHN_XINDEX (0xffff) and the actual index of the section name
		// string table section is contained in the sh_link field of the
		// section header at index 0.
		if int(header.Shstrndx) == int(SecIdxXindex) {
			if sh.Link > math.MaxUint16 {
				return Header{}, build.ErrBadShstrndx
			}
			header.Shstrndx = uint16(sh.Link)
			if header.Shstrndx < uint16(SecIdxReserveLo) || header.Shstrndx >= header.Shnum {
				return Header{}, build.ErrBadShstrndx
			}
		}
	}
	if err := header.Validate(); err != nil {
		return Header{}, err
	}
	return header, nil
}

// Read parses the underlying ELF file in r. It reads only the main ELF, section and prog segment headers.
// The ELF binary is expected to start at position 0 in the ReaderAt.
//
// Read keeps its tables from one binary to the next, growing them only for a
// binary with more headers than any before it. A caller holding its memory to
// a bound checks the counts with [File.ReadHeader] first. On error f is left
// describing no binary.
func (f *File) Read(r io.ReaderAt) error {
	// The tables are filled in place, so a failure partway would leave them
	// describing half of this binary under the last one's header.
	progs, sections := f.progs[:0], f.sections[:0]
	f.hdr, f.progs, f.sections = Header{}, progs, sections
	buf := f.buf[:]
	header, err := readHeader(r, buf)
	if err != nil {
		return err
	}
	bo := header.ByteOrder()

	phentsize := int64(header.Phentsize)
	progHeaderOff := int64(header.Phoff)
	progs = slicesGrow(progs, int(header.Phnum))
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
			return err
		}
		progs = append(progs, prog{
			ProgHeader: ph,
			sr:         *io.NewSectionReader(r, int64(ph.Off), int64(ph.SizeOnFile)),
		})
	}

	c := sliceCap[section](uint64(header.Shnum))
	if c < 0 {
		return build.ErrTooManySections
	}
	sections = slicesGrow(sections, c)
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
			return err
		}
		sections = append(sections, section{
			SectionHeader: sh,
			sr:            *io.NewSectionReader(r, int64(sh.Offset), int64(sh.SizeOnFile)),
		})
	}
	f.hdr, f.progs, f.sections = header, progs, sections
	return nil
}

// Header returns the ELF header.
func (f *File) Header() Header {
	return f.hdr
}

// Prog returns the program at progIdx index.
func (f *File) Prog(progIdx int) (FileProg, error) {
	if progIdx >= len(f.progs) || progIdx < 0 {
		return FileProg{}, build.ErrIndexOutOfRange
	}
	return FileProg{
		f:      f,
		pindex: progIdx,
	}, nil
}

// Section returns the section at sectionIdx index.
func (f *File) Section(sectionIdx int) (FileSection, error) {
	if sectionIdx >= len(f.sections) || sectionIdx < 0 {
		return FileSection{}, build.ErrIndexOutOfRange
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
		if s.NameEquals(name) {
			return s, nil
		}
	}
	return FileSection{}, build.ErrSectionNotFound
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
	return FileSection{}, build.ErrSectionNotFound
}

// FileSection is the handle to a file's section.
type FileSection struct {
	f      *File
	sindex int
}

func (fs FileSection) ptr() *section {
	return &fs.f.sections[fs.sindex]
}

// Index returns the index of the FileSection within the file among sections.
func (fs FileSection) Index() int { return fs.sindex }

// SectionHeader returns the section's header.
func (fs FileSection) SectionHeader() SectionHeader {
	return fs.ptr().SectionHeader
}

// Size returns the size of the ELF section body after decompression in bytes,
// or -1 if a compressed section's header could not be read.
func (fs FileSection) Size() int64 {
	s := fs.ptr()
	if s.Flags&SectionFlag(secFlagCompressed) != 0 {
		ch, _, err := fs.Compression()
		if err != nil {
			return -1
		}
		return ch.Size
	}
	return int64(s.SizeOnFile)
}

func (fs FileSection) AppendName(dst []byte) (_ []byte, err error) {
	return fs.f.AppendTableStr(dst, fs.ptr().Name)
}

// NameLen returns the length of the section's name.
func (fs FileSection) NameLen() (int, error) {
	shstr, err := fs.f.nameTable()
	if err != nil || shstr.f == nil {
		return 0, err
	}
	return shstr.strLen(int64(fs.ptr().Name))
}

// ReadName reads the section's name into dst, which [FileSection.NameLen]
// sizes, and returns its length. A dst too short for the name fails with
// [io.ErrShortBuffer]. Unlike [FileSection.AppendName] it never allocates.
func (fs FileSection) ReadName(dst []byte) (int, error) {
	shstr, err := fs.f.nameTable()
	if err != nil || shstr.f == nil {
		return 0, err
	}
	name, err := shstr.appendStr(dst[:0:len(dst)], int64(fs.ptr().Name), false)
	return len(name), err
}

// NameEquals reports whether the section is named name. The name is compared
// as it is read, through the File's scratch, so nothing is allocated however
// long it is. A name that cannot be read equals nothing.
func (fs FileSection) NameEquals(name string) bool {
	shstr, err := fs.f.nameTable()
	if err != nil {
		return false
	} else if shstr.f == nil {
		return name == "" // No string table: every section is unnamed.
	}
	return shstr.strEquals(int64(fs.ptr().Name), name)
}

// nameTable returns the section name string table, or a zero FileSection for a
// binary without one, whose sections are all unnamed.
func (f *File) nameTable() (FileSection, error) {
	strndx := int(f.hdr.Shstrndx)
	if strndx == 0 {
		return FileSection{}, nil
	}
	shstr, err := f.Section(strndx)
	if err != nil {
		return FileSection{}, err
	} else if shstr.ptr().Type != SecTypeStrTab {
		return FileSection{}, build.ErrNotStringTable
	}
	return shstr, nil
}

// strLen returns the length of the null-terminated string at start in string
// table fs, scanning through the File's scratch.
func (fs FileSection) strLen(start int64) (int, error) {
	size := fs.Size()
	if start < 0 || start >= size {
		return 0, build.ErrStringOutOfRange
	}
	for n := int64(0); start+n < size; {
		chunk, err := fs.readAt(fs.f.strbuf[:], start+n)
		if err != nil && err != io.ErrNoProgress {
			return 0, err
		} else if len(chunk) == 0 {
			break
		}
		if end := bytes.IndexByte(chunk, 0); end >= 0 {
			return int(n) + end, nil
		}
		n += int64(len(chunk))
	}
	return 0, build.ErrUnterminatedString
}

func (fs FileSection) Name() (string, error) {
	str, err := fs.AppendName(nil)
	if err != nil {
		return "", err
	}
	return string(str), nil
}

// Open returns a new [io.SectionReader] reading the ELF section body.
func (fs FileSection) Open() *io.SectionReader {
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
		return dst, build.ErrNoContents
	} else if s.Flags&SectionFlag(secFlagCompressed) != 0 {
		return dst, build.ErrCompressionUnsupported
	}
	sz := fs.Size()
	if sz == 0 {
		return dst, nil
	}
	if sliceCapWithSize(1, uint64(sz)) < 0 || sz+int64(len(dst)) > math.MaxInt {
		return dst, build.ErrSectionTooLarge
	}
	dst = slicesGrow(dst, int(sz))
	toRead := dst[len(dst) : len(dst)+int(sz)]

	result, err := fs.readAt(toRead, 0)
	if err != nil {
		return dst, err
	} else if len(result) != len(toRead) {
		return dst, io.ErrUnexpectedEOF
	}
	dst = dst[:len(dst)+int(sz)]
	return dst, nil
}

// FileProg is a handle to a prog segment in an ELF binary.
type FileProg struct {
	f      *File
	pindex int
}

func (fp FileProg) ptr() *prog {
	return &fp.f.progs[fp.pindex]
}

// ProgHeader returns the program segment's header.
func (fp FileProg) ProgHeader() ProgHeader {
	return fp.ptr().ProgHeader
}

// Size returns the size of the ELF program body after decompression in bytes.
func (fp FileProg) Size() int64 {
	return int64(fp.ptr().SizeOnFile) // Prog segments are never compressed.
}

// Open returns a new [io.ReadSeeker] reading the ELF program body.
func (fp FileProg) Open() io.ReadSeeker { return io.NewSectionReader(&fp.ptr().sr, 0, 1<<63-1) }

// readAt returns a buffer with fileSection contents with the underlying File's buffer.
func (fs FileSection) readAt(buf []byte, offset int64) ([]byte, error) {
	s := fs.ptr()
	if s.Type == SecTypeNobits {
		return nil, build.ErrNoContents
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
		return -1, build.ErrNotInSegment
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
				return -1, build.ErrSegmentAmbiguous
			}
			progIdx = i
		}
	}
	if progIdx < 0 {
		return -1, build.ErrNotInSegment
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

// AppendSymStr gets the null-terminated string starting at symName in the first SymbolTable section and appends it to dst and returns the result.
func (f *File) AppendSymStr(dst []byte, symName uint32) ([]byte, error) {
	symTab, err := f.SectionByType(SecTypeSymTab)
	if err != nil {
		return nil, err
	}
	symtabSh := symTab.SectionHeader()
	strTab, err := f.Section(int(symtabSh.Link))
	if err != nil {
		return nil, err
	}
	return strTab.appendStr(dst, int64(symName), true)
}

// AppendTableStr gets the null-terminated string starting at start in the ELF string table and appends it to dst and returns the result.
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
		return dst, build.ErrNotStringTable
	}
	dst, err = shstr.appendStr(dst, int64(start), true)
	if err != nil {
		return dst, err
	}
	return dst, nil
}

// strEquals reports whether the null-terminated string at start in string
// table fs is s, reading no more of it than could still match.
func (fs FileSection) strEquals(start int64, s string) bool {
	size := fs.Size()
	if start < 0 || start >= size {
		return false
	}
	for off := start; off < size; {
		// What is left of s and its terminator decide the match.
		chunk, err := fs.readAt(fs.f.strbuf[:min(len(fs.f.strbuf), len(s)+1)], off)
		if err != nil || len(chunk) == 0 {
			return false
		}
		end := bytes.IndexByte(chunk, 0)
		if end >= 0 {
			chunk = chunk[:end]
		}
		if len(chunk) > len(s) || string(chunk) != s[:len(chunk)] {
			return false
		}
		s = s[len(chunk):]
		if end >= 0 {
			return s == ""
		}
		off += int64(len(chunk))
	}
	return false // Unterminated.
}

// appendStr appends the null-terminated string at start in string table fs to
// dst, reading through the File's scratch. Without grow, a string that does not
// fit in dst's spare capacity fails with [io.ErrShortBuffer], so dst is never
// reallocated. On error dst comes back as it was passed.
func (fs FileSection) appendStr(dst []byte, start int64, grow bool) ([]byte, error) {
	n0 := len(dst)
	size := fs.Size()
	if start < 0 || start >= size {
		return dst, build.ErrStringOutOfRange
	}
	for off := start; off < size; {
		chunk, err := fs.readAt(fs.f.strbuf[:], off)
		if err != nil {
			return dst[:n0], err
		} else if len(chunk) == 0 {
			break
		}
		end := bytes.IndexByte(chunk, 0)
		if end >= 0 {
			chunk = chunk[:end]
		}
		if !grow && len(chunk) > cap(dst)-len(dst) {
			return dst[:n0], io.ErrShortBuffer
		}
		dst = append(dst, chunk...)
		if end >= 0 {
			return dst, nil
		}
		off += int64(len(chunk))
	}
	return dst[:n0], build.ErrUnterminatedString
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
	return 0, build.ErrNoContents
}

type unsupportedCompressionReader struct{}

func (*unsupportedCompressionReader) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, build.ErrCompressionUnsupported
}
