package build

import (
	"strings"
	"testing"
)

// TestErrorText checks every error has its own message: a constant without a
// line comment would make stringer fall back to the constant's name.
func TestErrorText(t *testing.T) {
	seen := make(map[string]buildErr)
	for e := buildErr(1); e <= ErrRelocUnsupported; e++ {
		msg := e.Error()
		if msg == "" || strings.HasPrefix(msg, "Err") || strings.HasPrefix(msg, "buildErr(") {
			t.Errorf("error %d has no message of its own: %q", e, msg)
		}
		if prev, dup := seen[msg]; dup {
			t.Errorf("errors %d and %d share the message %q", prev, e, msg)
		}
		seen[msg] = e
	}
}

func TestErrorAllocs(t *testing.T) {
	var err error
	allocs := testing.AllocsPerRun(10, func() {
		for e := buildErr(1); e <= ErrRelocUnsupported; e++ {
			err = e
		}
	})
	if allocs != 0 || err == nil {
		t.Errorf("returning a build error allocates %v times", allocs)
	}
}
