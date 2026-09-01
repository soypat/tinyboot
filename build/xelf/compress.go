package xelf

import (
	"io"
)

// Chdr sizes: an ELF32 header is 3 words, an ELF64 one is a word, a word of
// reserved padding, then two extended words.
const (
	chdrSize32 = 4 + 4 + 4
	chdrSize64 = 4 + 4 + 8 + 8
)

// CompressionHeader is the framing at the head of a SHF_COMPRESSED section,
// describing the payload that follows it.
type CompressionHeader struct {
	Type CompressionType
	// Size is the section's length once decompressed, which is exact -- a
	// caller can size its destination buffer once and never grow it.
	Size      int64
	Addralign int64
	// Len is the length of the header itself, and so the offset within the
	// section at which the compressed payload begins.
	Len int
}

// Compression returns the section's compression framing, reporting false for a
// section that is not compressed. A compressed section's bytes cannot be read
// through [FileSection.AppendData] or [FileSection.Open]; decompress the payload
// from [FileSection.OpenPayload] instead.
//
// The Go toolchain compresses DWARF by default, so this is the ordinary state of
// .debug_* in a gc-built binary rather than an exotic one.
func (fs FileSection) Compression() (ch CompressionHeader, compressed bool, err error) {
	s := fs.ptr()
	if s.Flags&SectionFlag(secFlagCompressed) == 0 {
		return ch, false, nil
	}
	class := fs.f.hdr.Class
	ch.Len = chdrSize32
	if class == Class64 {
		ch.Len = chdrSize64
	}
	if int64(s.SizeOnFile) < int64(ch.Len) {
		return ch, true, makeFormatErr(s.Offset, "section too short for compression header", s.SizeOnFile)
	}
	var buf [chdrSize64]byte
	if _, err := fs.readAt(buf[:ch.Len], 0); err != nil {
		return ch, true, err
	}
	bo := fs.f.hdr.ByteOrder()
	if class == Class64 {
		ch.Type = CompressionType(bo.Uint32(buf[0:4]))
		// buf[4:8] is ch_reserved.
		ch.Size = int64(bo.Uint64(buf[8:16]))
		ch.Addralign = int64(bo.Uint64(buf[16:24]))
	} else {
		ch.Type = CompressionType(bo.Uint32(buf[0:4]))
		ch.Size = int64(bo.Uint32(buf[4:8]))
		ch.Addralign = int64(bo.Uint32(buf[8:12]))
	}
	if ch.Size < 0 {
		return ch, true, makeFormatErr(s.Offset, "compressed section size overflows", ch.Size)
	}
	return ch, true, nil
}

// OpenPayload returns a reader over the section body past any compression
// header: exactly the bytes a decompressor consumes. For an uncompressed
// section it is the whole body, so a caller need not branch on compression to
// get at the data.
func (fs FileSection) OpenPayload() (*io.SectionReader, error) {
	s := fs.ptr()
	if s.Type == SecTypeNobits {
		return nil, errReadFromNobits
	}
	ch, compressed, err := fs.Compression()
	if err != nil {
		return nil, err
	}
	off := int64(0)
	if compressed {
		off = int64(ch.Len)
	}
	return io.NewSectionReader(&s.sr, off, int64(s.SizeOnFile)-off), nil
}
