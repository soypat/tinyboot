// Package xwasm decodes WebAssembly binary modules in the allocation-conscious
// style of [xelf].
//
// A module is a header followed by a sequence of sections, each an id and a
// size. There is no section header table: [File.Read] walks the sections once
// and keeps a small fixed-size record of each, never their contents. Everything
// of unbounded size -- section bodies, function bodies, names -- is either read
// through an [io.SectionReader], appended onto a caller-owned buffer, or
// streamed through a caller-owned window by [CodeReader] and [NameReader].
//
// DWARF in a WebAssembly module lives in custom sections named as in ELF
// (".debug_line", ".debug_info", ...), uncompressed and, in a linked module,
// already relocated. Its addresses are offsets from the start of the Code
// section's payload, the same space [Func.Offset] is expressed in.
//
// [xelf]: github.com/soypat/tinyboot/build/xelf
package xwasm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

const (
	fileBufSize = 512

	magic      uint32 = 0x00 | 'a'<<8 | 's'<<16 | 'm'<<24
	headerSize        = 8 // Magic and version.

	// maxSectionFrame is the largest a section's framing can be before its
	// payload: id (1), size (5) and, for a custom section, the name length (5).
	maxSectionFrame = 1 + 5 + 5

	// maxSections bounds how many sections [File.Read] will record. A section
	// can be as small as two bytes, so the count a file can claim grows with its
	// size; real modules carry a dozen standard sections and a handful of
	// custom ones. This mirrors xelf's safechunk guard.
	maxSections = 1 << 12
)

var (
	errBadMagic       = errors.New("bad magic number")
	errNoSection      = errors.New("section not found")
	errLEBTooLong     = errors.New("LEB128 encoding exceeds maximum length")
	errLEBOverflow    = errors.New("LEB128 value overflows its type")
	errTooManySecs    = errors.New("too many sections")
	errSectionPastEOF = errors.New("section extends past end of file")
)

// SectionID identifies the kind of a section. Every id but [SecCustom] may
// appear at most once in a module, in a fixed order.
type SectionID uint8

const (
	SecCustom    SectionID = 0
	SecType      SectionID = 1
	SecImport    SectionID = 2
	SecFunction  SectionID = 3
	SecTable     SectionID = 4
	SecMemory    SectionID = 5
	SecGlobal    SectionID = 6
	SecExport    SectionID = 7
	SecStart     SectionID = 8
	SecElement   SectionID = 9
	SecCode      SectionID = 10
	SecData      SectionID = 11
	SecDataCount SectionID = 12
	SecTag       SectionID = 13 // Exception handling proposal.
)

var sectionNames = [...]string{
	SecCustom:    "custom",
	SecType:      "type",
	SecImport:    "import",
	SecFunction:  "function",
	SecTable:     "table",
	SecMemory:    "memory",
	SecGlobal:    "global",
	SecExport:    "export",
	SecStart:     "start",
	SecElement:   "element",
	SecCode:      "code",
	SecData:      "data",
	SecDataCount: "datacount",
	SecTag:       "tag",
}

// sectionRank is the position a non-custom section must take in a module. Ids
// were assigned as sections were added to the spec, so they are not in order:
// the tag section sits between memory and global, datacount before code.
var sectionRank = [...]uint8{
	SecType:      1,
	SecImport:    2,
	SecFunction:  3,
	SecTable:     4,
	SecMemory:    5,
	SecTag:       6,
	SecGlobal:    7,
	SecExport:    8,
	SecStart:     9,
	SecElement:   10,
	SecDataCount: 11,
	SecCode:      12,
	SecData:      13,
}

func (id SectionID) String() string {
	if int(id) < len(sectionNames) {
		return sectionNames[id]
	}
	return "SectionID(" + strconv.Itoa(int(id)) + ")"
}

// Validate reports whether id is a section id this package knows.
func (id SectionID) Validate() error {
	if int(id) >= len(sectionNames) {
		return makeFormatErr(0, "unknown section id", uint8(id))
	}
	return nil
}

// Header is the module preamble: the magic number, which is checked rather
// than stored, and the binary format version.
type Header struct {
	Version uint32
}

// DecodeHeader decodes the module preamble at the start of buf.
func DecodeHeader(buf []byte) (h Header, n int, err error) {
	if len(buf) < headerSize {
		return Header{}, 0, errors.New("too short buffer to decode WASM header")
	}
	if binary.LittleEndian.Uint32(buf) != magic {
		return Header{}, 0, makeFormatErr(0, errBadMagic.Error(), buf[:4])
	}
	h.Version = binary.LittleEndian.Uint32(buf[4:])
	if h.Version != 1 {
		return Header{}, 0, makeFormatErr(4, "unsupported WASM version", h.Version)
	}
	return h, headerSize, nil
}

// Put encodes the module preamble into b.
func (h Header) Put(b []byte) (n int, err error) {
	if len(b) < headerSize {
		return 0, errors.New("buffer too short to put Header")
	}
	binary.LittleEndian.PutUint32(b, magic)
	binary.LittleEndian.PutUint32(b[4:], h.Version)
	return headerSize, nil
}

// HeaderSize returns the size of the module preamble in bytes.
func (h Header) HeaderSize() int { return headerSize }

// SectionHeader describes where a section sits in the file. Offsets are
// absolute file offsets.
type SectionHeader struct {
	ID SectionID
	// Start is the offset of the section's id byte.
	Start uint64
	// Offset is the offset of the section's contents: past the id and size
	// and, for a custom section, past its name.
	Offset uint64
	// Size is the size of the contents in bytes, which for a custom section
	// excludes the name.
	Size uint64
	// NameOff and NameLen locate a custom section's name. The name is not
	// stored: [FileSection.AppendName] reads it when asked, as xelf does with
	// string-table names.
	NameOff uint64
	NameLen uint32
}

// End returns the offset one past the section's last byte.
func (sh SectionHeader) End() uint64 { return sh.Offset + sh.Size }

// FrameSize returns the bytes the section spends on framing rather than
// contents: its id, size and, for a custom section, its name.
func (sh SectionHeader) FrameSize() uint64 { return sh.Offset - sh.Start }

// DecodeSectionHeader decodes the framing of the section whose id byte is at
// file offset start and at b[0]. n is the number of framing bytes decoded,
// which excludes a custom section's name: the name need not be in b.
func DecodeSectionHeader(b []byte, start uint64) (sh SectionHeader, n int, err error) {
	if len(b) == 0 {
		return sh, 0, errors.New("SectionHeader short decode buffer")
	}
	sh.ID = SectionID(b[0])
	if err = sh.ID.Validate(); err != nil {
		return sh, 0, makeFormatErr(start, "unknown section id", b[0])
	}
	size, k, err := DecodeULEB128(b[1:], 32)
	if err != nil {
		return sh, 0, makeFormatErr(start+1, "section size", err)
	}
	n = 1 + k
	sh.Start = start
	sh.Offset = start + uint64(n)
	sh.Size = size
	if sh.ID != SecCustom {
		return sh, n, nil
	}
	namelen, k, err := DecodeULEB128(b[n:], 32)
	if err != nil {
		return sh, 0, makeFormatErr(start+uint64(n), "custom section name length", err)
	}
	// The name is part of the payload the size counts.
	if uint64(k)+namelen > size {
		return sh, 0, makeFormatErr(start+uint64(n), "custom section name exceeds section", namelen)
	}
	sh.NameOff = sh.Offset + uint64(k)
	sh.NameLen = uint32(namelen)
	sh.Offset = sh.NameOff + namelen
	sh.Size = size - uint64(k) - namelen
	return sh, n + k, nil
}

// BufferTooSmallError reports a caller-owned buffer that cannot hold a single
// item the reader must present whole, and how large it would have to be. A
// caller can grow its buffer to Need and retry.
type BufferTooSmallError struct {
	Need int
	Have int
}

func (e BufferTooSmallError) Error() string {
	return "xwasm: buffer of " + strconv.Itoa(e.Have) +
		" bytes too small, need " + strconv.Itoa(e.Need)
}

func makeFormatErr(off uint64, msg string, val any) error {
	if str, ok := val.(fmt.Stringer); ok {
		val = str.String()
	}
	return fmt.Errorf("WASM format error: %s @ off=%d: %v", msg, off, val)
}
