package xwasm

import (
	"bytes"
	"os"
	"testing"
)

// fuzzState is everything a fuzz iteration touches, allocated once. The fuzz
// engine calls the target sequentially within a worker process, so one set
// serves every iteration: an iteration allocates nothing but what a module
// with more sections than any before it grows the section table by.
type fuzzState struct {
	r    bytes.Reader
	f    File
	cr   CodeReader
	nr   NameReader
	dr   DataReader
	cbuf [64]byte
	dbuf [64]byte
	nbuf [256]byte
}

func (s *fuzzState) run(data []byte) {
	s.r.Reset(data)
	if s.f.Read(&s.r) != nil {
		return
	}
	for i := 0; i < s.f.NumSections(); i++ {
		sec, _ := s.f.Section(i)
		sh := sec.SectionHeader()
		if sh.End() > uint64(len(data)) || sh.Offset < sh.Start {
			panic("section outside module")
		}
	}
	s.f.SectionByName(".debug_line")
	var size uint64 // A module without a Code section yields no functions.
	if code, err := s.f.SectionByID(SecCode); err == nil {
		size = code.SectionHeader().Size
	}
	if s.cr.Reset(&s.f, s.cbuf[:]) == nil {
		for fn := range s.cr.Funcs {
			if fn.End() > size {
				panic("function body outside code section")
			}
		}
	}
	if s.nr.Reset(&s.f, s.nbuf[:]) == nil {
		for range s.nr.FuncNames {
		}
		for range s.nr.DataNames {
		}
	}
	size = 0
	if data, err := s.f.SectionByID(SecData); err == nil {
		size = data.SectionHeader().Size
	}
	if s.dr.Reset(&s.f, s.dbuf[:]) == nil {
		for seg := range s.dr.Segments {
			if seg.End() > size {
				panic("data segment outside data section")
			}
		}
	}
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
// must stay at zero, since the fuzzer runs it flat out on every core.
func BenchmarkFuzzIteration(b *testing.B) {
	data, err := os.ReadFile(fixtures[0])
	if err != nil {
		b.Fatal(err)
	}
	var s fuzzState
	s.run(data)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		s.run(data)
	}
}
