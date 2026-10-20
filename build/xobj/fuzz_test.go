package xobj

import (
	"bytes"
	"os"
	"testing"
)

// fuzzState is everything a fuzz iteration touches, allocated once. The fuzz
// engine calls the target sequentially within a worker process, so one set
// serves every iteration. A binary with more headers than any before it grows
// the decoders' tables, bounded by xwasm's section cap and ELF's 16-bit
// counts; nothing else allocates.
type fuzzState struct {
	r    bytes.Reader
	f    File
	name [256]byte
}

func (s *fuzzState) run(data []byte) {
	s.r.Reset(data)
	if s.f.Read(&s.r) != nil {
		return
	}
	var total int64
	for sec := range s.f.Sections {
		// xwasm checks each section against the end of the module; xelf takes
		// section headers at their word, so an ELF section may claim bytes past
		// the end of the file and fail only when read.
		if s.f.Format() == FormatWasm && sec.Off+sec.Size > uint64(len(data)) {
			panic("section outside module")
		}
		total += int64(sec.Size)
		// A name too long for the buffer is refused, never grown into.
		s.f.ReadSectionName(s.name[:], sec.Index)
	}
	if s.f.Format() == FormatWasm && s.f.Err() == nil && total+s.f.HeaderBytes() != int64(len(data)) {
		panic("module sections do not tile the module")
	}
	for sym := range s.f.Symbols {
		s.f.ReadSymbolName(s.name[:], sym)
	}
	s.f.SectionIndex(".debug_line")
}

func FuzzRead(f *testing.F) {
	for _, name := range fixtures {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("\x00asm\x01\x00\x00\x00"))
	var s fuzzState
	f.Fuzz(func(t *testing.T, data []byte) {
		s.run(data)
	})
}

// BenchmarkFuzzIteration guards the fuzz target's allocation behavior: B/op
// must stay at zero on every fixture, since the fuzzer runs it flat out on every
// core.
func BenchmarkFuzzIteration(b *testing.B) {
	for _, name := range fixtures {
		data, err := os.ReadFile(name)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name[len("../../testdata/"):], func(b *testing.B) {
			var s fuzzState
			s.run(data)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				s.run(data)
			}
		})
	}
}
