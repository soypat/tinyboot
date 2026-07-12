package fsfuzz

import (
	"encoding/binary"
	"errors"
)

// FAT32 is the FAT variant that actually matters — it is what an SD card, a USB
// stick and a Raspberry Pi boot partition are formatted as — but
// github.com/soypat/fat cannot create one: Formatter.Format dispatches
// FormatFAT12, FormatFAT16 and FormatFAT32 to formatFAT, which is a stub
// returning frUnsupported. Its FAT32 *mount and file* code is complete and is
// what we want to fuzz, so the only thing missing is an image to mount.
//
// FormatFAT32 writes one. It is a mkfs, not a re-implementation of anything
// under test: nothing here is on the path of a single operation the fuzzer
// performs. If it produced a malformed image, mount would reject it and every
// test would fail loudly at the first line, so it needs no oracle of its own.
//
// Layout, which is the plainest FAT32 that exists:
//
//	sector 0            volume boot record (BPB)
//	sector 1            FSInfo
//	sector 6            backup boot record
//	sector 32           FAT #1              (fatSectors sectors)
//	sector 32+fatSecs   FAT #2
//	sector dataStart    cluster 2 = the root directory, empty
//
// A FAT is FAT32 if and only if it has more than 65525 clusters (fat's
// clustMaxFAT16; the same rule as FatFs and as Microsoft's spec). Nothing about
// the boot sector declares the variant — the driver counts the clusters and
// decides. So there is no such thing as a small FAT32: at the smallest legal
// cluster size, one sector, the volume is still 32 MiB. That floor is why the
// device this formats is sparse. See [RAM].
const (
	// Field offsets in the volume boot record. Named as in the Microsoft FAT
	// specification so they can be checked against it.
	bsJmpBoot     = 0  // 3 bytes.
	bsOEMName     = 3  // 8 bytes.
	bpbBytsPerSec = 11 // uint16.
	bpbSecPerClus = 13 // uint8.
	bpbRsvdSecCnt = 14 // uint16.
	bpbNumFATs    = 16 // uint8.
	bpbRootEntCnt = 17 // uint16. Must be 0 on FAT32.
	bpbTotSec16   = 19 // uint16. Must be 0 on FAT32.
	bpbMedia      = 21 // uint8.
	bpbFATSz16    = 22 // uint16. Must be 0 on FAT32.
	bpbSecPerTrk  = 24 // uint16.
	bpbNumHeads   = 26 // uint16.
	bpbHiddSec    = 28 // uint32.
	bpbTotSec32   = 32 // uint32.
	bpbFATSz32    = 36 // uint32.
	bpbExtFlags   = 40 // uint16.
	bpbFSVer      = 42 // uint16. Must be 0; fat rejects anything else.
	bpbRootClus   = 44 // uint32.
	bpbFSInfo     = 48 // uint16. fat only reads FSInfo if this is 1.
	bpbBkBootSec  = 50 // uint16.
	bsDrvNum      = 64 // uint8.
	bsBootSig     = 66 // uint8.
	bsVolID       = 67 // uint32.
	bsVolLab      = 71 // 11 bytes.
	bsFilSysType  = 82 // 8 bytes. fat's check_fs matches "FAT32   " here.
	bsSigOffset   = 510

	// FSInfo field offsets.
	fsiLeadSig   = 0
	fsiStrucSig  = 484
	fsiFreeCount = 488
	fsiNxtFree   = 492

	fsiLeadSigValue  = 0x41615252
	fsiStrucSigValue = 0x61417272
	bootSigValue     = 0xaa55
	unknownCount     = 0xffffffff

	// reservedSectors is 32, the value every FAT32 formatter uses: it leaves the
	// boot record, the FSInfo and the backup boot record room and keeps the FAT
	// aligned.
	reservedSectors = 32
	numFATs         = 2
	rootCluster     = 2

	// eoc marks the last cluster of a chain. bad and the two low entries are the
	// FAT32 reserved values; the top four bits of every entry are reserved and
	// must be left clear.
	eoc = 0x0fff_ffff
)

// FormatFAT32 writes a FAT32 filesystem onto bd, which must have sectors sectors
// of sectorSize bytes each, with one sector per cluster.
//
// It fails if the geometry cannot hold a FAT32, which is anything under about
// 32 MiB — see [MinFAT32Sectors].
func FormatFAT32(bd *RAM, sectorSize, sectors int) error {
	if sectorSize < 512 || sectorSize&(sectorSize-1) != 0 {
		return errors.New("fsfuzz: FAT32 sector size must be a power of two, at least 512")
	}
	fatSecs, _, err := fat32Geometry(sectorSize, sectors)
	if err != nil {
		return err
	}
	sec := make([]byte, sectorSize)

	// Volume boot record.
	//
	// The jump is not executable and does not need to be: fat's check_fs only
	// requires the first byte to be a jump opcode (0xEB, 0xE9 or 0xE8), the 0xAA55
	// signature at 510, and the string at 82. A real BIOS would run this, so use
	// the bytes a real formatter writes.
	copy(sec[bsJmpBoot:], []byte{0xeb, 0x58, 0x90})
	copy(sec[bsOEMName:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(sec[bpbBytsPerSec:], uint16(sectorSize))
	sec[bpbSecPerClus] = 1
	binary.LittleEndian.PutUint16(sec[bpbRsvdSecCnt:], reservedSectors)
	sec[bpbNumFATs] = numFATs
	binary.LittleEndian.PutUint16(sec[bpbRootEntCnt:], 0)
	binary.LittleEndian.PutUint16(sec[bpbTotSec16:], 0)
	sec[bpbMedia] = 0xf8 // Fixed disk.
	binary.LittleEndian.PutUint16(sec[bpbFATSz16:], 0)
	binary.LittleEndian.PutUint16(sec[bpbSecPerTrk:], 63)
	binary.LittleEndian.PutUint16(sec[bpbNumHeads:], 255)
	binary.LittleEndian.PutUint32(sec[bpbHiddSec:], 0)
	binary.LittleEndian.PutUint32(sec[bpbTotSec32:], uint32(sectors))
	binary.LittleEndian.PutUint32(sec[bpbFATSz32:], uint32(fatSecs))
	binary.LittleEndian.PutUint16(sec[bpbExtFlags:], 0) // Both FATs live, FAT #1 is the active one.
	binary.LittleEndian.PutUint16(sec[bpbFSVer:], 0)
	binary.LittleEndian.PutUint32(sec[bpbRootClus:], rootCluster)
	binary.LittleEndian.PutUint16(sec[bpbFSInfo:], 1)
	binary.LittleEndian.PutUint16(sec[bpbBkBootSec:], 6)
	sec[bsDrvNum] = 0x80
	sec[bsBootSig] = 0x29
	binary.LittleEndian.PutUint32(sec[bsVolID:], 0x1eaf_f00d) // Fixed: the image must be deterministic.
	copy(sec[bsVolLab:], "NO NAME    ")
	copy(sec[bsFilSysType:], "FAT32   ")
	binary.LittleEndian.PutUint16(sec[bsSigOffset:], bootSigValue)
	if err := writeSector(bd, sec, 0); err != nil {
		return err
	}
	if err := writeSector(bd, sec, 6); err != nil { // Backup boot record.
		return err
	}

	// FSInfo. fat reads the free-cluster count and the next-free hint out of this
	// and trusts them, so declare both unknown and let it count for itself rather
	// than hand it numbers this formatter would have to keep correct.
	fill(sec, 0)
	binary.LittleEndian.PutUint32(sec[fsiLeadSig:], fsiLeadSigValue)
	binary.LittleEndian.PutUint32(sec[fsiStrucSig:], fsiStrucSigValue)
	binary.LittleEndian.PutUint32(sec[fsiFreeCount:], unknownCount)
	binary.LittleEndian.PutUint32(sec[fsiNxtFree:], unknownCount)
	binary.LittleEndian.PutUint16(sec[bsSigOffset:], bootSigValue)
	if err := writeSector(bd, sec, 1); err != nil {
		return err
	}

	// First sector of each FAT: entry 0 is the media byte, entry 1 is reserved,
	// entry 2 is the root directory, which is one cluster long and therefore ends
	// immediately. Every other entry is free, which is zero — and zero is what the
	// rest of the FAT already reads as, except that it does not: erased media is
	// 0xff. So the FAT has to be written out in full, all fatSecs sectors of it,
	// twice. It is the one part of formatting that is not free, and it is why the
	// image is built once per process and copied. See pristineFAT32.
	fill(sec, 0)
	binary.LittleEndian.PutUint32(sec[0:], 0x0fff_ff00|uint32(0xf8))
	binary.LittleEndian.PutUint32(sec[4:], eoc)
	binary.LittleEndian.PutUint32(sec[8:], eoc) // Cluster 2: the root, end of chain.
	zero := make([]byte, sectorSize)
	for i := 0; i < numFATs; i++ {
		base := reservedSectors + i*fatSecs
		if err := writeSector(bd, sec, base); err != nil {
			return err
		}
		for s := 1; s < fatSecs; s++ {
			if err := writeSector(bd, zero, base+s); err != nil {
				return err
			}
		}
	}

	// The root directory: one empty cluster. An entry beginning with a zero byte
	// is the end of the directory, so a zeroed cluster is an empty directory.
	dataStart := reservedSectors + numFATs*fatSecs
	if err := writeSector(bd, zero, dataStart); err != nil {
		return err
	}
	return nil
}

// MinFAT32Sectors is the smallest number of sectorSize-byte sectors that can
// hold a FAT32 filesystem with one sector per cluster. There is no way to make a
// FAT32 smaller than this: the variant is defined by having more than 65525
// clusters, so the volume cannot be smaller than that many clusters plus its
// FATs.
func MinFAT32Sectors(sectorSize int) int {
	// Solve for the smallest total that leaves minClusters clusters after the
	// reserved sectors and both FATs, then add slack rather than iterate: one
	// extra FAT sector is cheaper than being one cluster short.
	const minClusters = 65526 // > fat's clustMaxFAT16 = 0xFFF5.
	entriesPerSector := sectorSize / 4
	fatSecs := (minClusters + 2 + entriesPerSector - 1) / entriesPerSector
	return reservedSectors + numFATs*fatSecs + minClusters
}

// fat32Geometry reports how many sectors each FAT takes and how many clusters
// are left over, using the same arithmetic fat's init_fat uses to decide the
// volume is FAT32 at all.
func fat32Geometry(sectorSize, sectors int) (fatSecs, clusters int, err error) {
	entriesPerSector := sectorSize / 4
	// The FAT has to describe the clusters, and the clusters are what is left over
	// after the FAT: solve it by taking the answer that is one FAT sector too
	// generous and letting the leftover clusters be however many they are.
	for fatSecs = 1; ; fatSecs++ {
		clusters = sectors - reservedSectors - numFATs*fatSecs
		if clusters <= 0 {
			return 0, 0, errors.New("fsfuzz: device too small for any FAT")
		}
		if (clusters+2+entriesPerSector-1)/entriesPerSector <= fatSecs {
			break // This FAT is big enough to describe the clusters it leaves.
		}
	}
	const minClusters = 65526
	if clusters < minClusters {
		return 0, 0, errors.New("fsfuzz: device too small for FAT32: a FAT32 volume must have more than 65525 clusters, see MinFAT32Sectors")
	}
	return fatSecs, clusters, nil
}

func writeSector(bd *RAM, sec []byte, at int) error {
	_, err := bd.WriteBlocks(sec, int64(at))
	return err
}
