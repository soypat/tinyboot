package gpt

import (
	"hash/crc32"
	"testing"
)

func TestGUIDStringRoundTrip(t *testing.T) {
	// Disk GUID from a real PolarFire SoC eMMC image: text form vs raw
	// on-disk bytes (first three fields little-endian).
	const text = "6B154DD2-116F-42FF-A314-E44EAD9312D0"
	raw := GUID{0xD2, 0x4D, 0x15, 0x6B, 0x6F, 0x11, 0xFF, 0x42, 0xA3, 0x14, 0xE4, 0x4E, 0xAD, 0x93, 0x12, 0xD0}
	if got := raw.String(); got != text {
		t.Errorf("String: got %s, want %s", got, text)
	}
	g, err := GUIDFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	if g != raw {
		t.Errorf("GUIDFromString: got %v, want %v", g, raw)
	}
	// Lower case accepted.
	if g, err = GUIDFromString("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"); err != nil || g != PartitionTypeEFISystem {
		t.Errorf("lower case parse: got %v, %v", g, err)
	}
	for _, bad := range []string{"", "6B154DD2-116F-42FF-A314-E44EAD9312D", "6B154DD2X116F-42FF-A314-E44EAD9312D0", "6B154DG2-116F-42FF-A314-E44EAD9312D0"} {
		if _, err := GUIDFromString(bad); err == nil {
			t.Errorf("GUIDFromString(%q): expected error", bad)
		}
	}
	if !PartitionTypeUnused.IsZero() || raw.IsZero() {
		t.Error("IsZero misbehaves")
	}
	if got := PartitionTypeLinuxFilesystem.PartitionTypeString(); got != "Linux filesystem" {
		t.Errorf("PartitionTypeString: got %q", got)
	}
}

func TestHeaderCalculateCRC(t *testing.T) {
	buf := make([]byte, 92)
	h, err := HeaderFromBytes(buf)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSize(92)
	h.SetCurrentLBA(1)
	h.SetBackupLBA(1000)
	h.SetDiskGUID(PartitionTypeLinuxFilesystem)
	h.SetCRC(0xDEADBEEF) // Must not influence the computed value.

	want := make([]byte, 92)
	copy(want, buf)
	want[16], want[17], want[18], want[19] = 0, 0, 0, 0
	if got, ref := h.CalculateCRC(), crc32.ChecksumIEEE(want); got != ref {
		t.Errorf("CalculateCRC: got %#08x, want %#08x", got, ref)
	}
	h.SetCRC(h.CalculateCRC())
	if h.CRC() != h.CalculateCRC() {
		t.Error("SetCRC(CalculateCRC()) does not validate")
	}
}

func TestPartitionEntryNameRoundTrip(t *testing.T) {
	buf := make([]byte, 128)
	pe, err := PartitionEntryFromBytes(buf)
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
	pe, err := PartitionEntryFromBytes(buf)
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
