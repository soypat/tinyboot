package main

import (
	"bytes"
	"strings"

	"github.com/soypat/tinyboot/build/xwasm"
)

// isGcWasm reports whether f was built by the gc toolchain rather than TinyGo.
// The gc linker writes a go:buildid section when it has a build ID, and names
// itself in the producers section.
func isGcWasm(f *xwasm.File) bool {
	if _, err := f.SectionByName("go:buildid"); err == nil {
		return true
	}
	s, err := f.SectionByName("producers")
	if err != nil || s.Size() > 4096 {
		return false
	}
	data, err := s.AppendData(nil)
	return err == nil && bytes.Contains(data, []byte("Go cmd/compile"))
}

// gcWasmPackageOf is [packageOf] for a module built by the gc toolchain, whose
// linker rewrites every character of a function name outside [A-Za-z0-9_.] to
// '_' (cmd/link/internal/wasm/asm.go). "github.com/google/gopacket/layers.init"
// arrives as "github.com_google_gopacket_layers.init" and
// "time.(Duration).Truncate" as "time.__Duration_.Truncate", so there is no
// slash left to find the package by.
//
// The package still ends at a recoverable dot. A path keeps dots only in
// elements before its last -- gc escapes the last element's as %2e, arriving
// as "_2e" -- and in practice only in the first, a module's domain. So when a
// name's first '_' comes before its first dot, that dot ends the package:
// "crypto_internal_fips140_nistec_fiat.p521Mul", "net_http.Get". When the dot
// comes first it is ambiguous: "github.com_google_gopacket_layers.init" opens
// with a domain, "time.__Duration_.Truncate" with a whole package. Paths
// without a domain are the standard library's and main, whose roots are a
// short fixed list; anything else is taken to start with a domain and to end
// at the first dot after its first separator.
//
// Paths are reported as mangled rather than restored: '_' is ambiguous between
// a separator and an underscore the path really had.
func gcWasmPackageOf(sym string) string {
	if pkg, ok := bucketOf(sym); ok {
		return pkg
	}
	dot := strings.IndexByte(sym, '.')
	if dot <= 0 {
		return cPackage
	}
	under := strings.IndexByte(sym, '_')
	if under < 0 || under > dot && stdRoots[sym[:dot]] {
		return sym[:dot]
	}
	if under < dot {
		return sym[:dot] // Separators precede the first dot: no domain.
	}
	end := strings.IndexByte(sym[under:], '.')
	if end < 0 {
		return cPackage
	}
	return sym[:under+end]
}

// stdRoots are the first path elements of the standard library, plus main and
// the prefixes of the gc toolchain's own symbols ("type:", "go:"), which arrive
// as "type_" and "go_" and so never reach the lookup with a dot first.
var stdRoots = map[string]bool{
	"archive": true, "arena": true, "bufio": true, "builtin": true, "bytes": true,
	"cmp": true, "compress": true, "container": true, "context": true, "crypto": true,
	"database": true, "debug": true, "embed": true, "encoding": true, "errors": true,
	"expvar": true, "flag": true, "fmt": true, "go": true, "hash": true, "html": true,
	"image": true, "index": true, "internal": true, "io": true, "iter": true, "log": true,
	"main": true, "maps": true, "math": true, "mime": true, "net": true, "os": true,
	"path": true, "plugin": true, "reflect": true, "regexp": true, "runtime": true,
	"simd": true, "slices": true, "sort": true, "strconv": true, "strings": true,
	"structs": true, "sync": true, "syscall": true, "testing": true, "text": true,
	"time": true, "unicode": true, "unique": true, "unsafe": true, "vendor": true,
	"weak": true,
}
