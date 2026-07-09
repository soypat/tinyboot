/*
package mbr implements a Master Boot Record parser and writer.
*/
package mbr

import (
	"encoding/binary"
	"errors"
)

//go:generate stringer -type PartitionType -linecomment -output stringers.go

// PartitionType refers to the type of partition the Partition Table Entry refers to.
type PartitionType byte

const (
	PartitionTypeUnused        PartitionType = 0x00 // unused
	PartitionTypeFAT12         PartitionType = 0x01 // fat12
	PartitionTypeFAT16Small    PartitionType = 0x04 // fat16 <32MB
	PartitionTypeExtended      PartitionType = 0x05 // extended
	PartitionTypeFAT16         PartitionType = 0x06 // fat16
	PartitionTypeNTFS          PartitionType = 0x07 // ntfs/exfat
	PartitionTypeFAT32CHS      PartitionType = 0x0B // fat32-chs
	PartitionTypeFAT32LBA      PartitionType = 0x0C // fat32-lba
	PartitionTypeFAT16LBA      PartitionType = 0x0E // fat16-lba
	PartitionTypeExtendedLBA   PartitionType = 0x0F // extended-lba
	PartitionTypeWindowsRE     PartitionType = 0x27 // windows-recovery
	PartitionTypeLinuxSwap     PartitionType = 0x82 // linux-swap
	PartitionTypeLinux         PartitionType = 0x83 // linux
	PartitionTypeLinuxExtended PartitionType = 0x85 // linux-extended
	PartitionTypeLinuxLVM      PartitionType = 0x8E // linux-lvm
	PartitionTypeFreeBSD       PartitionType = 0xA5 // freebsd
	PartitionTypeOpenBSD       PartitionType = 0xA6 // openbsd
	PartitionTypeNetBSD        PartitionType = 0xA9 // netbsd
	PartitionTypeAppleBoot     PartitionType = 0xAB // apple-boot
	PartitionTypeAppleHFS      PartitionType = 0xAF // apple-hfs
	PartitionTypeSolaris       PartitionType = 0xBF // solaris
	PartitionTypeGPTProtective PartitionType = 0xEE // gpt-protective
	PartitionTypeEFISystem     PartitionType = 0xEF // efi-system
	PartitionTypeLinuxRAID     PartitionType = 0xFD // linux-raid
)

const (
	bootstrapLen     = 440
	uniqueDiskIDOff  = bootstrapLen
	uniqueDiskIDLen  = 4
	reservedLen      = 2
	pteOffset        = bootstrapLen + uniqueDiskIDLen + reservedLen
	pteLen           = 16 // partition table entry length
	bootSignatureOff = 510
	BootSignature    = 0xAA55
)

// BootSectorFromBytes converts a byte slice to an MBR BootSector while maintaining a
// reference to the original byte slice. The byte slice must be at least 512
// bytes long and the first byte of the slice must be the first byte of the MBR.
func BootSectorFromBytes(start []byte) (BootSector, error) {
	if len(start) < 512 {
		return BootSector{}, errors.New("boot sector too short")
	}
	bs := BootSector{
		data: start[:512:512],
	}
	return bs, nil
}

// BootSector is a Master Boot Record. It contains the bootstrap code, the partition table and a boot signature.
type BootSector struct {
	data []byte
}

// PartitionTableEntry represents one of the four partition table entries in the MBR.
// It contains information about the partition, such as the type, size, location and if it is bootable.
// See https://en.wikipedia.org/wiki/Master_boot_record#PTE for more information.
type PartitionTableEntry struct {
	data [pteLen]byte
}

// Bootstrap returns bytes 0..439 of the MBR containing the binary executable code.
func (mbr *BootSector) Bootstrap() []byte {
	return mbr.data[0:bootstrapLen]
}

// UniqueDiskID returns the 32-bit disk signature used by operating systems to identify the disk.
func (mbr *BootSector) UniqueDiskID() uint32 {
	return binary.LittleEndian.Uint32(mbr.data[uniqueDiskIDOff : uniqueDiskIDOff+uniqueDiskIDLen])
}

// SetUniqueDiskID sets the 32-bit disk signature.
func (mbr *BootSector) SetUniqueDiskID(id uint32) {
	binary.LittleEndian.PutUint32(mbr.data[uniqueDiskIDOff:uniqueDiskIDOff+uniqueDiskIDLen], id)
}

// BootSignature returns the boot signature of the MBR. This is a magic number (0xAA55) that indicates that this is a valid MBR.
func (mbr *BootSector) BootSignature() uint16 {
	return binary.LittleEndian.Uint16(mbr.data[bootSignatureOff : bootSignatureOff+2])
}

// SetBootSignature sets the boot signature of the MBR. Write [BootSignature] (0xAA55) to mark the MBR valid.
func (mbr *BootSector) SetBootSignature(sig uint16) {
	binary.LittleEndian.PutUint16(mbr.data[bootSignatureOff:bootSignatureOff+2], sig)
}

// IsProtectiveMBR returns true if the first partition of the MBR is a GPT protective MBR.
// In this case the MBR is not used for booting and the GUID Partition Table can be found in the next LBA.
func (mbr *BootSector) IsGPTProtective() bool {
	return PartitionType(mbr.data[pteOffset+4]) == PartitionTypeGPTProtective
}

// PartitionTable returns the idx'th partition table entry of the MBR.
func (mbr *BootSector) PartitionTable(idx int) PartitionTableEntry {
	if idx > 3 {
		panic("invalid partition table index")
	}
	pte := PartitionTableEntry{}
	copy(pte.data[:], mbr.data[pteOffset+idx*pteLen:pteOffset+(idx+1)*pteLen])
	return pte
}

// SetPartitionTable sets the idx'th partition table entry of the MBR.
func (mbr *BootSector) SetPartitionTable(idx int, pte PartitionTableEntry) {
	if idx > 3 {
		panic("invalid partition table index")
	}
	copy(mbr.data[pteOffset+idx*pteLen:pteOffset+(idx+1)*pteLen], pte.data[:])
}

// MakePartitionTableEntry creates a new partition table entry from the given parameters.
func MakePartitionTableEntry(attrs DriveAttributes, Type PartitionType, startLBA, numLBA uint32, startCHS, lastCHS CHS) PartitionTableEntry {
	pte := PartitionTableEntry{}
	pte.data[0] = byte(attrs)
	pte.data[4] = byte(Type)
	binary.LittleEndian.PutUint32(pte.data[8:12], startLBA)
	binary.LittleEndian.PutUint32(pte.data[12:16], numLBA)
	pte.data[1], pte.data[2], pte.data[3] = startCHS.Tuple()
	pte.data[5], pte.data[6], pte.data[7] = lastCHS.Tuple()
	return pte
}

// Attributes returns the attributes of the partition the PTE refers to.
func (pte *PartitionTableEntry) Attributes() DriveAttributes {
	return DriveAttributes(pte.data[0])
}

// SetAttributes sets the attributes of the partition the PTE refers to.
func (pte *PartitionTableEntry) SetAttributes(attrs DriveAttributes) {
	pte.data[0] = byte(attrs)
}

// CHSStart returns the starting sector of the partition in CHS format. Is not used by modern operating systems.
func (pte *PartitionTableEntry) CHSStart() CHS {
	return CHS(pte.data[1]) | CHS(pte.data[2])<<8 | CHS(pte.data[3])<<16
}

// SetCHSStart sets the starting sector of the partition in CHS format.
func (pte *PartitionTableEntry) SetCHSStart(chs CHS) {
	pte.data[1], pte.data[2], pte.data[3] = chs.Tuple()
}

// PartitionType returns the type the partition refers to, such as if the partition is
// formatted as a FAT32, NTFS, exFAT, Linux etc.
func (pte *PartitionTableEntry) PartitionType() PartitionType {
	return PartitionType(pte.data[4])
}

// SetPartitionType sets the type of the partition the PTE refers to.
func (pte *PartitionTableEntry) SetPartitionType(t PartitionType) {
	pte.data[4] = byte(t)
}

// CHSLast returns the last sector of the partition in CHS format.
func (pte *PartitionTableEntry) CHSLast() CHS {
	return CHS(pte.data[5]) | CHS(pte.data[6])<<8 | CHS(pte.data[7])<<16
}

// SetCHSLast sets the last sector of the partition in CHS format.
func (pte *PartitionTableEntry) SetCHSLast(chs CHS) {
	pte.data[5], pte.data[6], pte.data[7] = chs.Tuple()
}

// StartLBA returns the starting sector of the partition in LBA format (logical block address).
func (pte *PartitionTableEntry) StartLBA() uint32 {
	return binary.LittleEndian.Uint32(pte.data[8:12])
}

// SetStartLBA sets the starting sector of the partition in LBA format.
func (pte *PartitionTableEntry) SetStartLBA(lba uint32) {
	binary.LittleEndian.PutUint32(pte.data[8:12], lba)
}

// NumberOfLBA returns the number of sectors (logical block addresses) in the partition.
func (pte *PartitionTableEntry) NumberOfLBA() uint32 {
	return binary.LittleEndian.Uint32(pte.data[12:16])
}

// SetNumberOfLBA sets the number of sectors (logical block addresses) in the partition.
func (pte *PartitionTableEntry) SetNumberOfLBA(n uint32) {
	binary.LittleEndian.PutUint32(pte.data[12:16], n)
}

// IsBootable returns true if the partition the PTE refers to is bootable.
func (attrs DriveAttributes) IsBootable() bool {
	return DriveAttrsBootable&attrs != 0
}

// CHS is a cylinder-head-sector address. This addressing scheme is deprecated by modern operating systems
// in favor of LBA, or Logical Block Addressing.
type CHS uint32

// Tuple returns the three bytes composing the CHS address as stored in a partition table entry.
func (chs CHS) Tuple() (cylinder, head, sector uint8) {
	return uint8(chs), uint8(chs >> 8), uint8(chs >> 16)
}

// NewCHS creates a new CHS address from the cylinder, head and sector numbers. See "CHS addressing".
func NewCHS(cylinder, head, sector uint8) CHS {
	return CHS(cylinder) | CHS(head)<<8 | CHS(sector)<<16
}

// DriveAttributes refers to the first byte of a Partition Table Entry. It specifies
// if the partition is bootable.
type DriveAttributes byte

const (
	DriveAttrsBootable DriveAttributes = 1 << 7
)
