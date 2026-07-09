package mbr

import "testing"

func TestBootSectorSettersRoundTrip(t *testing.T) {
	buf := make([]byte, 512)
	bs, err := BootSectorFromBytes(buf)
	if err != nil {
		t.Fatal(err)
	}
	bs.SetUniqueDiskID(0x416DA8A4)
	bs.SetBootSignature(BootSignature)
	if got := bs.UniqueDiskID(); got != 0x416DA8A4 {
		t.Errorf("UniqueDiskID: got %#08x", got)
	}
	if got := bs.BootSignature(); got != BootSignature {
		t.Errorf("BootSignature: got %#04x", got)
	}

	var pte PartitionTableEntry
	pte.SetAttributes(DriveAttrsBootable)
	pte.SetPartitionType(PartitionTypeGPTProtective)
	pte.SetCHSStart(NewCHS(0, 0, 2))
	pte.SetCHSLast(NewCHS(0xFF, 0xFF, 0xFF))
	pte.SetStartLBA(1)
	pte.SetNumberOfLBA(15273599)
	bs.SetPartitionTable(0, pte)

	got := bs.PartitionTable(0)
	if !got.Attributes().IsBootable() {
		t.Error("attributes: not bootable")
	}
	if got.PartitionType() != PartitionTypeGPTProtective {
		t.Errorf("type: got %v", got.PartitionType())
	}
	if got.CHSStart() != NewCHS(0, 0, 2) || got.CHSLast() != NewCHS(0xFF, 0xFF, 0xFF) {
		t.Errorf("CHS: got %#06x..%#06x", uint32(got.CHSStart()), uint32(got.CHSLast()))
	}
	if got.StartLBA() != 1 || got.NumberOfLBA() != 15273599 {
		t.Errorf("LBA: got start %d num %d", got.StartLBA(), got.NumberOfLBA())
	}
	if !bs.IsGPTProtective() {
		t.Error("IsGPTProtective: false after setting protective PTE")
	}
	// Setters must match MakePartitionTableEntry byte for byte.
	made := MakePartitionTableEntry(DriveAttrsBootable, PartitionTypeGPTProtective, 1, 15273599, NewCHS(0, 0, 2), NewCHS(0xFF, 0xFF, 0xFF))
	if made != pte {
		t.Error("setters and MakePartitionTableEntry disagree")
	}
}
