// Package build holds what the binary-format packages beneath it share: the
// errors they return.
package build

//go:generate stringer -linecomment -output=stringers.go -type=buildErr

// buildErr is an error the build packages return. Its values are constants
// below 256, which the runtime boxes into an interface from a static table, so
// returning one never allocates: not on a hot path, and not when a fuzzer feeds
// malformed input on every core.
//
// An error names what went wrong and nothing more. It carries no offset or
// offending value; a caller that needs to know where a walk failed tracks the
// position itself.
//
// Short buffers and short reads are reported with [io.ErrShortBuffer] and
// [io.ErrUnexpectedEOF], which are just as free to return.
type buildErr uint8

func (e buildErr) Error() string { return e.String() }

const (
	_ buildErr = iota

	// Lookups.
	ErrIndexOutOfRange // index out of range
	ErrSectionNotFound // section not found
	ErrNoSymbols       // no symbols
	ErrNoDebugLine     // no debug line
	ErrNotRead         // no binary: Read not called or failed
	ErrUnknownFormat   // unknown format

	// Strings and string tables.
	ErrNotStringTable     // not a string table
	ErrStringOutOfRange   // string offset out of range
	ErrUnterminatedString // unterminated string

	// Headers.
	ErrBadMagic             // bad magic
	ErrBadVersion           // unsupported version
	ErrVersionMismatch      // ident and header versions differ
	ErrBadClass             // unknown class
	ErrBadDataEncoding      // unknown data encoding
	ErrHeaderOffsetOverflow // header table offset overflows int64
	ErrShnumWithoutTable    // section count without section table
	ErrBadShstrndx          // section name table index out of range
	ErrPhentsizeTooSmall    // program header entry size too small
	ErrShentsizeTooSmall    // section header entry size too small
	ErrBadInitialSection    // initial section not null
	ErrBadExtendedShnum     // extended section count too small
	ErrProgOverflow         // program offset or size overflows int64
	ErrSectionOverflow      // section offset or size overflows int64
	ErrClass32Overflow      // field overflows 32-bit class

	// Sections and their layout.
	ErrUnknownSectionID    // unknown section id
	ErrSectionOrder        // section out of order or duplicated
	ErrBadSectionName      // section name exceeds section
	ErrSectionTooLarge     // section too large
	ErrTooManySections     // too many sections
	ErrSectionPastEOF      // section past end of file
	ErrPastSectionEnd      // read past end of section
	ErrSubsectionTooLarge  // subsection exceeds section
	ErrTrailingBytes       // trailing bytes in section
	ErrCountExceedsSection // count exceeds section size
	ErrNoContents          // section has no contents in file
	ErrNotInSegment        // section not in a segment
	ErrSegmentAmbiguous    // section in multiple segments
	ErrBadSegmentFlags     // bad segment flags

	// Tables of fixed-size entries.
	ErrEmptySymbolTable // empty symbol table
	ErrBadEntsize       // entry size mismatch
	ErrTableNotMultiple // table size not multiple of entry size
	ErrBadLink          // symbol table link not a string table

	// Encodings.
	ErrLEBTooLong             // LEB128 too long
	ErrLEBOverflow            // LEB128 overflows type
	ErrShortCompressionHeader // section too short for compression header
	ErrCompressedSizeOverflow // compressed size overflows int64
	ErrCompressionUnsupported // unsupported compression
	ErrNonConstantExpr        // non-constant instruction in constant expression
	ErrNonConstantSIMD        // non-constant SIMD instruction in constant expression
	ErrBadLimits              // bad limits flags
	ErrUnknownImportKind      // unknown import kind
	ErrIndexSpaceOverflow     // function index space overflows uint32
	ErrNamesOutOfOrder        // names out of order

	// Relocations.
	ErrNoRelocationData    // empty relocation data
	ErrNoRelocationSymbols // no symbols for relocation
	ErrRelocUnsupported    // relocation unsupported for machine
)
