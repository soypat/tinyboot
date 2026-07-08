package gpt

import "testing"

func TestPartitionEntryNameRoundTrip(t *testing.T) {
	buf := make([]byte, 128)
	pe, err := ToPartitionEntry(buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"boot", "root", "", "a", "espαñol"} {
		if err := pe.SetNameUTF8([]byte(name)); err != nil {
			t.Fatalf("SetNameUTF8(%q): %v", name, err)
		}
		out := make([]byte, 72*3)
		n, err := pe.ReadNameAsUTF8(out)
		if err != nil {
			t.Fatalf("ReadNameAsUTF8 after SetNameUTF8(%q): %v", name, err)
		}
		if got := string(out[:n]); got != name {
			t.Errorf("name round trip: got %q, want %q", got, name)
		}
	}
}

func TestPartitionEntryNameRawUTF16(t *testing.T) {
	// "boot" as on-disk UTF-16LE followed by residual bytes from a longer
	// previous name ("primary"), as seen on real GPT disks. The read must
	// stop at the NUL code unit, not at the zero high byte of 'b'.
	buf := make([]byte, 128)
	name := []byte{'b', 0, 'o', 0, 'o', 0, 't', 0, 0, 0, 'r', 0, 'y', 0}
	copy(buf[56:], name)
	pe, err := ToPartitionEntry(buf)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 72*3)
	n, err := pe.ReadNameAsUTF8(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out[:n]); got != "boot" {
		t.Errorf("got %q, want %q", got, "boot")
	}
}
