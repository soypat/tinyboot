package picobin

import "fmt"

type ImageDef struct {
	Item
}

func MakeImageDef(img ImageType, exesec ExeSec, execpu ExeCPU, exechip ExeChip, tryBeforeYouBuy bool) ImageDef {
	return ImageDef{Item: rawMakeItem(ItemTypeImageDef, 1,
		uint8(0b111&img)|uint8((0b11&exesec)<<4),
		0b111&uint8(execpu)|(uint8(0b111&exechip)<<4)|b2u8(tryBeforeYouBuy)<<7,
		nil,
	)}
}

type ImageType uint8

const (
	ImageTypeInvalid    ImageType = iota // invalid
	ImageTypeExecutable                  // executable
	ImageTypeData                        // data
)

type ExeCPU uint8

const (
	ExeCPUARM   ExeCPU = iota // ARM
	ExeCPURISCV               // RISCV
)

type ExeSec uint8

const (
	ExeSecNonSecure ExeSec = iota // Non-Secure
	ExeSecSecure                  // Secure
)

type ExeChip uint8

const (
	ExeChipRP2040 ExeChip = iota // RP2040
	ExeChipRP2350                // RP2350
)

func (imgdef ImageDef) ImageType() ImageType {
	return ImageType(imgdef.SizeAndSpecial) & 0b111
}

func (imgdef ImageDef) ExeSec() ExeSec {
	return ExeSec(imgdef.SizeAndSpecial>>4) & 0b111
}

func (imgdef ImageDef) ExeCPU() ExeCPU {
	return ExeCPU(imgdef.TypeData) & 0b111
}

func (imgdef ImageDef) ExeChip() ExeChip {
	return ExeChip(imgdef.TypeData>>4) & 0b111
}

func (imgdef ImageDef) TryBeforeYouBuy() bool {
	return imgdef.TypeData&(1<<7) != 0
}

func (imgdef ImageDef) String() string {
	if imgdef.TryBeforeYouBuy() {
		return fmt.Sprintf("ImgDef(%s, %s, %s, %s, TBYB)",
			imgdef.ImageType().String(), imgdef.ExeSec().String(), imgdef.ExeCPU().String(), imgdef.ExeChip().String())
	}
	return fmt.Sprintf("ImgDef(%s, %s, %s, %s)",
		imgdef.ImageType().String(), imgdef.ExeSec().String(), imgdef.ExeCPU().String(), imgdef.ExeChip().String())
}

func rawMakeItem(head ItemType, szMod, szDivOrData, tpdata uint8, data []byte) Item {
	sizeAndSpecial := uint16(szMod) | uint16(szDivOrData)<<8
	item := Item{
		Head: uint8(head), SizeAndSpecial: sizeAndSpecial, TypeData: tpdata, Data: data,
	}
	if item.Size() != len(data)+4 {
		panic("bad rawMakeItem size data")
	}
	return item
}

// LoadMap is an optional item with a similar representation to the ELF program header. This is used both to define the content to hash,
// and also to "load" data before image execution (e.g. a secure flash binary can be loaded into RAM prior to both
// signature check and execution).
//
// The load map is a collection of runtime address, physical address, size and flags.
//  1. For a "packaged" binary, the information tells the bootrom where to load the code/data.
//  2. For a hashed or signed binary, the runtime addresses and size indicate code/data that must be included in the
//     hash to be verified or signature checked.
type LoadMap struct {
	Item
}

func (lm LoadMap) String() string {
	entries := lm.NumEntries()
	if entries < 0 {
		return "InvalidLoadMap()"
	}
	return fmt.Sprintf("LoadMap(abs=%v, entries=%d)", lm.Absolute(), entries)
}

func (lm LoadMap) Absolute() bool {
	return lm.Item.TypeData&1 != 0
}

func (lm LoadMap) NumEntries() int {
	entries := lm.SizeWords() - 1
	entries2 := lm.TypeData >> 1
	if entries != int(entries2) {
		return -1
	}
	return entries
}

// LoadMapEntry specifies a binary blob to be loaded. All addresses must be word aligned and sizes a multiple of word size (4 for RP2040 and RP2350).
type LoadMapEntry struct {
	StorageStartAbsOrRel uint32 // Storage start address relative to this word if not absolute, absolute storage start address if absolute.
	RuntimeStartAbs      uint32 // Absolute runtime start address.
	SizeOrEndAbs         uint32 // Size in bytes if not absolute, storage end address if absolute.
}
