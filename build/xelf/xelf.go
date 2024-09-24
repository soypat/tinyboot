package xelf

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Indexes into the Header.Ident array.
const (
	Magic         uint32 = 0x1
	offClass             = 4  // Class of machine.
	offData              = 5  // Data format.
	offVersion           = 6  // ELF format version.
	offOSABI             = 7  // Operating system / ABI identification
	offABIVersion        = 8  // ABI version
	offPad               = 9  // Start of padding (per SVR4 ABI).
	offType              = 16 // Start of file type after Nident array.
	offMachine           = 18

	// Size dependent offsets.

	offEntry32     = 16 // unsafe.Offsetof(Header32{}.Entry)
	offPhoff32     = 20 // unsafe.Offsetof(Header32{}.Phoff)
	offShoff32     = 24 // unsafe.Offsetof(Header32{}.Shoff)
	offFlags32     = 28 // unsafe.Offsetof(Header32{}.Flags)
	offEhsize32    = 32 // unsafe.Offsetof(Header32{}.Ehsize)
	offPhentsize32 = 34 // unsafe.Offsetof(Header32{}.Phentsize)
	offPhnum32     = 36 // unsafe.Offsetof(Header32{}.Phnum)
	offShentsize32 = 38 // unsafe.Offsetof(Header32{}.Shentsize)
	offShnum32     = 40 // unsafe.Offsetof(Header32{}.Shnum)
	offShstrndx32  = 42 // unsafe.Offsetof(Header32{}.Shstrndx)

	offEntry64     = 16 // unsafe.Offsetof(Header64{}.Entry)
	offPhoff64     = 24 // unsafe.Offsetof(Header64{}.Phoff)
	offShoff64     = 32 // unsafe.Offsetof(Header64{}.Shoff)
	offFlags64     = 40 // unsafe.Offsetof(Header64{}.Flags)
	offEhsize64    = 44 // unsafe.Offsetof(Header64{}.Ehsize)
	offPhentsize64 = 46 // unsafe.Offsetof(Header64{}.Phentsize)
	offPhnum64     = 48 // unsafe.Offsetof(Header64{}.Phnum)
	offShentsize64 = 50 // unsafe.Offsetof(Header64{}.Shentsize)
	offShnum64     = 52 // unsafe.Offsetof(Header64{}.Shnum)
	offShstrndx64  = 54 // unsafe.Offsetof(Header64{}.Shstrndx)
)

type File struct {
	Header
	buf       [512]byte
	byteorder binary.ByteOrder
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

func (fexist *File) Read(r io.ReaderAt) (*File, error) {
	var f File
	header := &f.Header
	buf := f.buf[:]
	if _, err := r.ReadAt(buf[:64], 0); err != nil {
		return nil, err
	}
	if buf[0] != '\x7f' || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F' {
		return nil, makeFormatErr(0, "bad magic number", buf[0:4])
	}

	header.Class = Class(buf[offClass])
	if f.Class != Class32 && f.Class != Class64 {
		return nil, makeFormatErr(offClass, "unknown ELF class", f.Class)
	}

	var bo binary.ByteOrder
	header.Data = Data(buf[offData])
	switch header.Data {
	case Data2LSB:
		bo = binary.LittleEndian
	case Data2MSB:
		bo = binary.BigEndian
	default:
		return nil, makeFormatErr(offData, "unknown ELF data encoding", f.Data)
	}
	f.byteorder = bo

	header.Version = Version(buf[offVersion])
	if header.Version != VersionCurrent {
		return nil, makeFormatErr(offVersion, "unknown ELF version", header.Version)
	}

	header.OSABI = OSABI(buf[offOSABI])
	header.ABIVersion = buf[offABIVersion]
	header.Type = Type(bo.Uint16(buf[offType:]))
	header.Machine = Machine(bo.Uint16(buf[offMachine:]))

	var phoff, shoff, fileOff int64
	var phentsize, phnum, shentsize, shnum, shstrndx int

	switch header.Class {
	case Class32:
		fileOff = 52
		header.Entry = uint64(bo.Uint16(buf[offEntry32:]))
		header.Phoff = uint64(bo.Uint32(buf[offPhoff32:]))
		header.Phentsize = uint16(bo.Uint16(buf[offPhentsize32:]))
		header.Phnum = bo.Uint16(buf[offPhnum32:])
		header.Shoff = uint64(bo.Uint32(buf[offShoff32:]))
		header.Shnum = bo.Uint16(buf[offShnum32:])
		header.Shstrndx = bo.Uint16(buf[offShstrndx32:])
	case Class64:
		fileOff = 64
		header.Entry = bo.Uint64(buf[offEntry64:])
		header.Phoff = bo.Uint64(buf[offPhoff64:])
		header.Phentsize = uint16(bo.Uint16(buf[offPhentsize64:]))
		header.Phnum = bo.Uint16(buf[offPhnum64:])
		header.Shoff = bo.Uint64(buf[offShoff64:])
		header.Shnum = bo.Uint16(buf[offShnum64:])
		header.Shstrndx = bo.Uint16(buf[offShstrndx64:])
	}
	return nil, nil
}

func makeFormatErr(off uint64, msg string, val any) error {
	return fmt.Errorf("off=%d %s: %v", off, msg, val)
}
