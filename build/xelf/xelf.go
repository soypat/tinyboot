package xelf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Indexes into the Header.Ident array.
const (
	magicLE       uint32 = 0x7f | 'E'<<8 | 'L'<<16 | 'F'<<24
	offClass             = 4  // Class of machine.
	offData              = 5  // Data format.
	offVersion           = 6  // ELF format version.
	offOSABI             = 7  // Operating system / ABI identification
	offABIVersion        = 8  // ABI version
	offPad               = 9  // Start of padding (per SVR4 ABI).
	offType              = 16 // Start of file type after Nident array.
	offMachine           = 18
	offVersionDup        = 20 // ELF format version after IDENT section.

	// Size dependent offsets.

	offEntry32     = 24 // unsafe.Offsetof(elf.Header32{}.Entry)
	offPhoff32     = 28 // unsafe.Offsetof(elf.Header32{}.Phoff)
	offShoff32     = 32 // unsafe.Offsetof(elf.Header32{}.Shoff)
	offFlags32     = 36 // unsafe.Offsetof(elf.Header32{}.Flags)
	offEhsize32    = 40 // unsafe.Offsetof(elf.Header32{}.Ehsize)
	offPhentsize32 = 42 // unsafe.Offsetof(elf.Header32{}.Phentsize)
	offPhnum32     = 44 // unsafe.Offsetof(elf.Header32{}.Phnum)
	offShentsize32 = 46 // unsafe.Offsetof(elf.Header32{}.Shentsize)
	offShnum32     = 48 // unsafe.Offsetof(elf.Header32{}.Shnum)
	offShstrndx32  = 50 // unsafe.Offsetof(elf.Header32{}.Shstrndx)

	offEntry64     = 24 // unsafe.Offsetof(elf.Header64{}.Entry)
	offPhoff64     = 32 // unsafe.Offsetof(elf.Header64{}.Phoff)
	offShoff64     = 40 // unsafe.Offsetof(elf.Header64{}.Shoff)
	offFlags64     = 48 // unsafe.Offsetof(elf.Header64{}.Flags)
	offEhsize64    = 52 // unsafe.Offsetof(elf.Header64{}.Ehsize)
	offPhentsize64 = 54 // unsafe.Offsetof(elf.Header64{}.Phentsize)
	offPhnum64     = 56 // unsafe.Offsetof(elf.Header64{}.Phnum)
	offShentsize64 = 58 // unsafe.Offsetof(elf.Header64{}.Shentsize)
	offShnum64     = 60 // unsafe.Offsetof(elf.Header64{}.Shnum)
	offShstrndx64  = 62 // unsafe.Offsetof(elf.Header64{}.Shstrndx)

	progHeaderSize64 = 48 + 8

	offPType32   = 0  // unsafe.Offsetof(elf.Prog32{}.Type)
	offPOff32    = 4  // unsafe.Offsetof(elf.Prog32{}.Off)
	offPVaddr32  = 8  // unsafe.Offsetof(elf.Prog32{}.Vaddr)
	offPPaddr32  = 12 // unsafe.Offsetof(elf.Prog32{}.Paddr)
	offPFilesz32 = 16 // unsafe.Offsetof(elf.Prog32{}.Filesz)
	offPMemsz32  = 20 // unsafe.Offsetof(elf.Prog32{}.Memsz)
	offPFlags32  = 24 // unsafe.Offsetof(elf.Prog32{}.Flags)
	offPAlign32  = 28 // unsafe.Offsetof(elf.Prog32{}.Align)

	progHeaderSize32 = 28 + 4

	offPType64   = 0  // unsafe.Offsetof(elf.Prog64{}.Type)
	offPFlags64  = 4  // unsafe.Offsetof(elf.Prog64{}.Flags)
	offPOff64    = 8  // unsafe.Offsetof(elf.Prog64{}.Off)
	offPVaddr64  = 16 // unsafe.Offsetof(elf.Prog64{}.Vaddr)
	offPPaddr64  = 24 // unsafe.Offsetof(elf.Prog64{}.Paddr)
	offPFilesz64 = 32 // unsafe.Offsetof(elf.Prog64{}.Filesz)
	offPMemsz64  = 40 // unsafe.Offsetof(elf.Prog64{}.Memsz)
	offPAlign64  = 48 // unsafe.Offsetof(elf.Prog64{}.Align)

	sectionHeaderSize32 = 36 + 4

	offSName32      = 0  // unsafe.Offsetof(elf.Section32{}.Name)
	offSType32      = 4  // unsafe.Offsetof(elf.Section32{}.Type)
	offSFlags32     = 8  // unsafe.Offsetof(elf.Section32{}.Flags)
	offSAddr32      = 12 // unsafe.Offsetof(elf.Section32{}.Addr)
	offSOff32       = 16 // unsafe.Offsetof(elf.Section32{}.Off)
	offSSize32      = 20 // unsafe.Offsetof(elf.Section32{}.Size)
	offSLink32      = 24 // unsafe.Offsetof(elf.Section32{}.Link)
	offSInfo32      = 28 // unsafe.Offsetof(elf.Section32{}.Info)
	offSAddralign32 = 32 // unsafe.Offsetof(elf.Section32{}.Addralign)
	offSEntsize32   = 36 // unsafe.Offsetof(elf.Section32{}.Entsize)

	sectionHeaderSize64 = 56 + 8

	offSName64      = 0  // unsafe.Offsetof(elf.Section64{}.Name)
	offSType64      = 4  // unsafe.Offsetof(elf.Section64{}.Type)
	offSFlags64     = 8  // unsafe.Offsetof(elf.Section64{}.Flags)
	offSAddr64      = 16 // unsafe.Offsetof(elf.Section64{}.Addr)
	offSOff64       = 24 // unsafe.Offsetof(elf.Section64{}.Off)
	offSSize64      = 32 // unsafe.Offsetof(elf.Section64{}.Size)
	offSLink64      = 40 // unsafe.Offsetof(elf.Section64{}.Link)
	offSInfo64      = 44 // unsafe.Offsetof(elf.Section64{}.Info)
	offSAddralign64 = 48 // unsafe.Offsetof(elf.Section64{}.Addralign)
	offSEntsize64   = 56 // unsafe.Offsetof(elf.Section64{}.Entsize)
)

var (
	errInvalidClass = errors.New("invalid ELF class")
)

type File struct {
	hdr      Header
	progs    []Prog
	sections []Section
	buf      [512]byte
}

type Header struct {
	Class      Class
	Data       Data
	Version    Version
	OSABI      OSABI
	ABIVersion uint8
	Type       Type
	Machine    Machine
	// Version uint32 // Always 1, equal to above.
	Entry     uint64
	Phoff     uint64 // Program header file offset.
	Shoff     uint64 // Section header file offset.
	Flags     uint32 // Architecture-specific flags.
	Ehsize    uint16 // Size of ELF header in bytes.
	Phentsize uint16 // Size of program header entry.
	Phnum     uint16 // Number of program header entries.
	Shentsize uint16 // Size of section header entry.
	Shnum     uint16 // Number of section header entries.
	Shstrndx  uint16 // Section name strings section.
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
	err = header.Validate()
	if err != nil {
		return err
	}

	phentsize := int64(header.Phentsize)
	progHeaderOff := int64(header.Phoff)
	bo := header.ByteOrder()
	progs := make([]Prog, header.Phnum)
	for i := int64(0); i < int64(header.Phnum); i++ {
		var p Prog
		progOff := i * phentsize
		fileOff := progHeaderOff + progOff
		n, err := r.ReadAt(buf[:progHeaderSize64], fileOff)
		if err != nil {
			return err
		}
		ph, _, err := DecodeProgHeader(buf[:n], header.Class, bo)
		if err != nil {
			return err
		}
		err = ph.Validate()
		if err != nil {
			return makeFormatErr(uint64(fileOff), err.Error(), ph)
		}
		progs[i] = Prog{
			hdr: ph,
			r:   *io.NewSectionReader(r, int64(ph.Off), int64(p.hdr.Filesz)),
		}
	}

	// If the number of sections is greater than or equal to SHN_LORESERVE
	// (0xff00), shnum has the value zero and the actual number of section
	// header table entries is contained in the sh_size field of the section
	// header at index 0.
	shnum := int(header.Shnum)
	shstrndx := int(header.Shstrndx)
	if header.Shoff > 0 && header.Shnum == 0 {
		n, err := r.ReadAt(buf[:sectionHeaderSize64], int64(header.Shoff))
		if err != nil {
			return makeFormatErr(header.Shoff, err.Error(), n)
		}
		sh, _, err := DecodeSectionHeader(buf[:n], header.Class, bo)
		if err != nil {
			return makeFormatErr(header.Shoff, err.Error(), sh)
		}
		err = sh.Validate()
		if err != nil {
			return makeFormatErr(header.Shoff, err.Error(), sh)
		}
		shnum = int(sh.FileSize)

		if sh.Type != SecTypeNull {
			return makeFormatErr(header.Shoff, "invalid type of the initial section", sh.Type)
		} else if shnum < int(SecIdxReserveLo) {
			return makeFormatErr(header.Shoff, "invalid shnum contained in sh_size", shnum)
		}
		// If the section name string table section index is greater than or
		// equal to SHN_LORESERVE (0xff00), this member has the value
		// SHN_XINDEX (0xffff) and the actual index of the section name
		// string table section is contained in the sh_link field of the
		// section header at index 0.
		if int(header.Shstrndx) == int(SecIdxXindex) {
			shstrndx = int(sh.Link)
			if shstrndx < int(SecIdxReserveLo) {
				return makeFormatErr(header.Shoff, "invalid shstrndx contained in sh_link", shstrndx)
			}
		}
	}
	c := sliceCap[Section](uint64(shnum))
	if c < 0 {
		return makeFormatErr(0, "too many sections", shnum)
	}
	sections := make([]Section, c)
	shentsize := int64(header.Shentsize)
	sectBase := int64(shnum) * shentsize
	for i := int64(0); i < int64(shnum); i++ {
		sectOff := i * int64(header.Shentsize)
		fileOff := sectBase + sectOff
		n, err := r.ReadAt(buf[:sectionHeaderSize64], fileOff)
		if err != nil {
			return err
		}
		sh, _, err := DecodeSectionHeader(buf[:n], header.Class, bo)
		if err != nil {
			return err
		}
		err = sh.Validate()
		if err != nil {
			return makeFormatErr(uint64(fileOff), err.Error(), err)
		}
		sections[i] = Section{
			hdr: sh,
			sr:  *io.NewSectionReader(r, int64(sh.Offset), int64(sh.FileSize)),
		}
	}
	*f = File{
		hdr:      header,
		progs:    progs,
		sections: sections,
	}
	return nil
}

// func (f *File) SectionName(sectionIdx int) string {

// }

func (h *Header) ByteOrder() (bo binary.ByteOrder) {
	switch h.Data {
	case Data2LSB:
		bo = binary.LittleEndian
	case Data2MSB:
		bo = binary.BigEndian
	default:
		panic("unsupported ELF Data ByteOrder")
	}
	return bo
}

func (h *Header) Validate() (err error) {
	if h.Class != Class32 && h.Class != Class64 {
		return makeFormatErr(offClass, "invalid class", h.Class)
	}
	if h.Shoff > math.MaxInt64 {
		err = makeFormatErr(0, "shoff overflows int64", h.Shoff)
	}
	if h.Phoff > math.MaxInt64 {
		err = errors.Join(err, makeFormatErr(0, "phoff overflows int64", h.Phoff))
	}
	if h.Shoff == 0 && h.Shnum != 0 {
		err = errors.Join(err, makeFormatErr(0, "invalid shnum for shoff=0", h.Shnum))
	}
	if h.Shnum > 0 && h.Shstrndx >= h.Shnum {
		err = errors.Join(err, makeFormatErr(0, "invalid shstrndx", h.Shstrndx))
	}
	var wantPhentSize, wantShentSize uint16
	switch h.Class {
	case Class32:
		wantPhentSize = 8 * 4
		wantShentSize = 10 * 4
	case Class64:
		wantPhentSize = 2*4 + 6*8
		wantShentSize = 4*4 + 6*8
	}
	if h.Phnum > 0 && h.Phentsize < wantPhentSize {
		err = errors.Join(err, makeFormatErr(0, "invalid phentsize", h.Phentsize))
	}
	if h.Shnum > 0 && h.Shentsize < wantShentSize {
		err = errors.Join(err, makeFormatErr(0, "invalid shentsize", h.Phentsize))
	}
	return err
}

func DecodeHeader(buf []byte) (header Header, n int, err error) {
	if magicLE != binary.LittleEndian.Uint32(buf[0:]) {
		return Header{}, 0, makeFormatErr(0, "bad magic number", buf[0:4])
	}

	header.Class = Class(buf[offClass])
	if header.Class != Class32 && header.Class != Class64 {
		return Header{}, 0, makeFormatErr(offClass, "unknown ELF class", header.Class)
	}

	header.Data = Data(buf[offData])
	bo := header.ByteOrder()
	if bo == nil {
		return Header{}, 0, makeFormatErr(offData, "unknown ELF data encoding", header.Data)
	}
	header.Version = Version(buf[offVersion])
	if header.Version != VersionCurrent {
		return Header{}, 0, makeFormatErr(offVersion, "unknown ELF version", header.Version)
	}

	header.OSABI = OSABI(buf[offOSABI])
	header.ABIVersion = buf[offABIVersion]
	header.Type = Type(bo.Uint16(buf[offType:]))
	header.Machine = Machine(bo.Uint16(buf[offMachine:]))

	version := bo.Uint32(buf[offVersionDup:])
	if version != uint32(header.Version) {
		return Header{}, 0, makeFormatErr(offVersionDup, "ELF IDENT version mismatch", header.Version)
	}
	// var phoff, shoff, fileOff int64
	// var phentsize, phnum, shentsize, shnum, shstrndx int
	switch header.Class {
	case Class32:
		n = 52
		header.Entry = uint64(bo.Uint16(buf[offEntry32:]))
		header.Phoff = uint64(bo.Uint32(buf[offPhoff32:]))
		header.Phentsize = uint16(bo.Uint16(buf[offPhentsize32:]))
		header.Phnum = bo.Uint16(buf[offPhnum32:])
		header.Shoff = uint64(bo.Uint32(buf[offShoff32:]))
		header.Shnum = bo.Uint16(buf[offShnum32:])
		header.Shstrndx = bo.Uint16(buf[offShstrndx32:])
	case Class64:
		n = 64
		header.Entry = bo.Uint64(buf[offEntry64:])
		header.Phoff = bo.Uint64(buf[offPhoff64:])
		header.Phentsize = bo.Uint16(buf[offPhentsize64:])
		header.Phnum = bo.Uint16(buf[offPhnum64:])
		header.Shoff = bo.Uint64(buf[offShoff64:])
		header.Shnum = bo.Uint16(buf[offShnum64:])
		header.Shstrndx = bo.Uint16(buf[offShstrndx64:])
	}

	return header, n, nil
}

type ProgFlag uint32

type ProgHeader struct {
	Type   ProgType
	Flags  ProgFlag
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

func DecodeProgHeader(b []byte, class Class, bo binary.ByteOrder) (ph ProgHeader, n int, err error) {
	switch class {
	case Class32:
		if len(b) < progHeaderSize32 {
			return ph, 0, errors.New("ProgHeader short decode buffer")
		}
		ph.Type = ProgType(bo.Uint32(b[offPType32:]))
		ph.Flags = ProgFlag(bo.Uint32(b[offPFlags32:]))
		ph.Off = uint64(bo.Uint32(b[offPOff32:]))
		ph.Vaddr = uint64(bo.Uint32(b[offPVaddr32:]))
		ph.Paddr = uint64(bo.Uint32(b[offPPaddr32:]))
		ph.Filesz = uint64(bo.Uint32(b[offPFilesz32:]))
		ph.Memsz = uint64(bo.Uint32(b[offPMemsz32:]))
		ph.Align = uint64(bo.Uint32(b[offPAlign32:]))
		n = progHeaderSize32
	case Class64:
		if len(b) < progHeaderSize64 {
			return ph, 0, errors.New("ProgHeader short decode buffer")
		}
		ph.Type = ProgType(bo.Uint32(b[offPType64:]))
		ph.Flags = ProgFlag(bo.Uint32(b[offPFlags64:]))
		ph.Off = bo.Uint64(b[offPOff64:])
		ph.Vaddr = bo.Uint64(b[offPVaddr64:])
		ph.Paddr = bo.Uint64(b[offPPaddr64:])
		ph.Filesz = bo.Uint64(b[offPFilesz64:])
		ph.Memsz = bo.Uint64(b[offPMemsz64:])
		ph.Align = bo.Uint64(b[offPAlign64:])
		n = progHeaderSize64
	default:
		return ph, 0, errInvalidClass
	}
	return ph, n, nil
}

func (ph *ProgHeader) Validate() (err error) {
	if ph.Off > math.MaxInt64 {
		err = errors.Join(err, errors.New("program header offset overflows int64"))
	}
	if ph.Filesz > math.MaxInt64 {
		err = errors.Join(err, errors.New("program header file size overflows int64"))
	}
	return err
}

type Prog struct {
	hdr ProgHeader
	r   io.SectionReader
}

func makeFormatErr(off uint64, msg string, val any) error {
	return fmt.Errorf("off=%d %s: %v", off, msg, val)
}

type SectionFlag uint64

// A SectionHeader represents a single ELF section header.
type SectionHeader struct {
	Name   uint32
	Type   SectionType
	Flags  SectionFlag
	Addr   uint64
	Offset uint64
	// Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64

	// FileSize is the size of this section in the file in bytes.
	// If a section is compressed, FileSize is the size of the
	// compressed data, while Size (above) is the size of the
	// uncompressed data.
	FileSize uint64
}

func DecodeSectionHeader(b []byte, class Class, bo binary.ByteOrder) (sh SectionHeader, n int, err error) {
	switch class {
	case Class32:
		if len(b) < sectionHeaderSize32 {
			return sh, 0, errors.New("SectionHeader short decode buffer")
		}
		sh.Name = bo.Uint32(b[offSName32:])
		sh.Type = SectionType(bo.Uint32(b[offSType32:]))
		sh.Flags = SectionFlag(bo.Uint32(b[offSFlags32:]))
		sh.Addr = uint64(bo.Uint32(b[offSAddr32:]))
		sh.Offset = uint64(bo.Uint32(b[offSOff32:]))
		sh.FileSize = uint64(bo.Uint32(b[offSSize32:]))
		sh.Link = bo.Uint32(b[offSLink32:])
		sh.Info = bo.Uint32(b[offSInfo32:])
		sh.Addralign = uint64(bo.Uint32(b[offSAddralign32:]))
		sh.Entsize = uint64(bo.Uint32(b[offSEntsize32:]))
		n = sectionHeaderSize32
	case Class64:
		if len(b) < sectionHeaderSize64 {
			return sh, 0, errors.New("SectionHeader short decode buffer")
		}
		sh.Name = bo.Uint32(b[offSName64:])
		sh.Type = SectionType(bo.Uint32(b[offSType64:]))
		sh.Flags = SectionFlag(bo.Uint64(b[offSFlags64:]))
		sh.Addr = bo.Uint64(b[offSAddr64:])
		sh.Offset = bo.Uint64(b[offSOff64:])
		sh.FileSize = bo.Uint64(b[offSSize64:])
		sh.Link = bo.Uint32(b[offSLink64:])
		sh.Info = bo.Uint32(b[offSInfo64:])
		sh.Addralign = bo.Uint64(b[offSAddralign64:])
		sh.Entsize = bo.Uint64(b[offSEntsize64:])
		n = sectionHeaderSize64
	default:
		return sh, 0, errInvalidClass
	}
	return sh, n, nil
}

func (sh *SectionHeader) Validate() (err error) {
	if sh.Offset > math.MaxInt64 {
		err = errors.New("section header offset overflows int64")
	}
	if sh.FileSize > math.MaxInt64 {
		err = errors.Join(err, errors.New("section header size(on file) overflows int64"))
	}
	return err
}

type Section struct {
	hdr SectionHeader
	sr  io.SectionReader
}
