package picobin

import "fmt"

type Item struct {
	Head uint8 // [0:1]:size_flag(0 means 1 byte size, 1 means 2 byte size) [1:7]: item type.
	// Contains size and special data.
	// [0:8]: s0%256
	// [8:16]: s0/256 if size_flag==1, or is type specific data for blocks that are never >256 words.
	SizeAndSpecial uint16
	TypeData       uint8  // Type specific data.
	Data           []byte // Item data.
}

// HeaderBytes returns the first 4 bytes of the item header as a static array.
func (it Item) HeaderBytes() [4]byte {
	return [4]byte{it.Head, byte(it.SizeAndSpecial), byte(it.SizeAndSpecial >> 8), it.TypeData}
}

func (it Item) Validate() error {
	sz := it.Size()
	if sz != 4+len(it.Data) {
		return fmt.Errorf("item size %d, but have %d data", sz, len(it.Data))
	}
	return nil
}

type ItemType uint8

// ItemType definitions.
const (
	ItemTypeVectorTable        ItemType = 0x03 // vector table
	ItemTypeRollingWindowDelta ItemType = 0x05 // rolling window delta
	ItemTypeRollingLoadMap     ItemType = 0x06 // load map
	ItemTypeSignature          ItemType = 0x09 // signature
	ItemTypePartitionTable     ItemType = 0x0A // partition table
	ItemTypeSalt               ItemType = 0x0C // salt

	ItemTypeNextBlockOffset ItemType = 0x41 // next block offset
	ItemTypeImageDef        ItemType = 0x42 // image def
	ItemTypeEntryPoint      ItemType = 0x44 // entry point
	ItemTypeHashDef         ItemType = 0x47 // hash def
	ItemTypeVersion         ItemType = 0x48 // version
	ItemTypeHashValue       ItemType = 0x4b // hash value
)

// ItemType definitions for 2 byte items.
const (
	ItemTypeIgnored ItemType = 0x7e // ignored
	ItemTypeLast    ItemType = 0x7f // last
)

func (it Item) sizeflag() bool { return it.Head&maskByteSize2 != 0 }

// Size returns the size in bytes of the item.
func (it Item) Size() int {
	return it.SizeWords() * 4
}

// SizeWords returns the size in words (4 bytes each) of the item.
func (it Item) SizeWords() int {
	if it.sizeflag() {
		return int(it.SizeAndSpecial)
	}
	return int(it.SizeAndSpecial & 0xff)
}

func (it Item) ItemType() ItemType { return ItemType(it.Head & 0x7f) }

func (it Item) String() string {
	switch it.ItemType() {
	case ItemTypeImageDef:
		return ImageDef{Item: it}.String()
	case ItemTypeRollingLoadMap:
		return LoadMap{Item: it}.String()
	}
	return fmt.Sprintf("Item(%s, size=%d)", it.ItemType(), it.Size())
}

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

func rawMakeItem(itemtype ItemType, szMod, szDivOrData, tpdata uint8, data []byte) Item {
	var szmask uint8
	if itemtype == ItemTypeIgnored || itemtype == ItemTypeLast || len(data) > 255 {
		szmask = maskByteSize2
	}
	sizeAndSpecial := uint16(szMod) | uint16(szDivOrData)<<8
	item := Item{
		Head: uint8(itemtype) | szmask, SizeAndSpecial: sizeAndSpecial, TypeData: tpdata, Data: data,
	}
	err := item.Validate()
	if err != nil {
		panic(err.Error())
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
	return fmt.Sprintf("LoadMap(abs=%v, entries=%d)", lm.IsAbsolute(), entries)
}

func (lm LoadMap) IsAbsolute() bool {
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

func makeIgnoredItem() Item {
	return rawMakeItem(ItemTypeIgnored, 1, 0, 0, nil)
}
