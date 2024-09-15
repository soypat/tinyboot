package picobin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

//go:generate stringer -type="ImageType,ExeCPU,ExeChip,ExeSec,ItemType" -linecomment -output stringers.go .

// Block delimiters. Are encoded as little endian like all picobin data. They were chosen to be numbers that were very unlikely to appear in ARM machine code.
const (
	BlockMarkerStart = 0xffffded3
	BlockMarkerEnd   = 0xab123579
)

var (
	startMarker = binary.LittleEndian.AppendUint32(nil, BlockMarkerStart)
	endMarker   = binary.LittleEndian.AppendUint32(nil, BlockMarkerEnd)
)

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

func (it Item) sizeflag() bool { return it.Head&1 != 0 }

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

type Block struct {
	// Items is a list of items not including the ItemTypeLast item.
	Items []Item
	// Link item specifies relative position in bytes of next block header relative to this block's header.
	// Set to 0 to form loop with self (specifying 1 block)
	Link int
}

func (b Block) String() string {
	return fmt.Sprintf("%s link=%d", b.Items, b.Link)
}

// NextBlockIdx returns the start and end indices of the next block.
func NextBlockIdx(text []byte) (int, int, error) {
	start := bytes.Index(text, startMarker)
	if start < 0 {
		end := bytes.Index(text, endMarker)
		if end >= 0 {
			return -1, end, errors.New("end marker found with no start marker")
		}
		return -1, -1, errors.New("block start marker not found")
	}
	end := bytes.Index(text[start:], endMarker)
	if end < 0 {
		return -1, -1, errors.New("block end marker not found")
	}
	end += start + 4 // Make end index absolute and add size of marker.
	return start, end, nil
}

func DecodeBlock(text []byte) (Block, int, error) {
	if len(text) < 12 {
		return Block{}, 0, errors.New("buffer shorter than minimum block size")
	}
	header := binary.LittleEndian.Uint32(text)
	if header != BlockMarkerStart {
		return Block{}, 0, errors.New("not start of block, missing start marker")
	}
	n := 4
	block := Block{}
	for n < len(text) {
		item, itemLen, err := DecodeNextItem(text[n:])
		if err != nil {
			return block, n, fmt.Errorf("bad item: %w", err)
		}
		block.Items = append(block.Items, item)
		n += itemLen
		if item.ItemType() == ItemTypeLast {
			itemSize := n - 4 - 4 // Subtract header and last item sizes.
			if item.Size() != itemSize {
				return block, n, fmt.Errorf("expected last item size %d, got %d", itemSize, item.Size())
			} else if len(text)-n < 8 {
				return block, n, errors.New("short buffer, unable to parse block link/footer")
			}
			block.Link = int(int32(binary.LittleEndian.Uint32(text[n:])))
			n += 4
			expectFooter := binary.LittleEndian.Uint32(text[n:])
			if expectFooter != BlockMarkerEnd {
				block.Items = block.Items[:len(block.Items)-1] // Discard LastItem type.
				return block, n, errors.New("block footer does not match end marker")
			}
			n += 4
			break
		}
	}
	if len(block.Items) == 0 {
		return block, n, errors.New("found no items in block?")
	} else if block.Items[len(block.Items)-1].ItemType() != ItemTypeLast {
		return block, n, errors.New("found no last item type")
	}
	block.Items = block.Items[:len(block.Items)-1] // Discard LastItem type.
	return block, n, nil
}

func DecodeNextItem(blockText []byte) (Item, int, error) {
	if len(blockText) < 4 {
		return Item{}, 0, errors.New("malformed short item")
	}
	item := Item{
		Head:           blockText[0],
		SizeAndSpecial: binary.LittleEndian.Uint16(blockText[1:]),
		TypeData:       blockText[3],
	}
	if item.ItemType() == ItemTypeLast {
		return item, 4, nil
	}
	size := item.Size()
	if size > len(blockText) {
		return Item{}, 0, fmt.Errorf("item %s size %d exceeds text", item.ItemType().String(), size)
	} else if size < 4 {
		return Item{}, 0, fmt.Errorf("item %s size %d subword size", item.ItemType().String(), size)
	} else if size > 4 {
		item.Data = blockText[4:size]
	}
	return item, size, nil
}

// func makeLOADMAP(absolute bool, entries []loadMapEntry) {
// 	sizeWords := 1 + len(entries)
// 	head := item{head: 0x06, s0mod: uint8(sizeWords % 256), s0div: uint8(sizeWords / 256), tpdata: b2u8(absolute) | uint8(len(entries))<<1}
// 	for i := range entries {
// 		head.data = binary.LittleEndian.AppendUint32(head.data, entries[i].storageStartAddr)
// 		head.data = binary.LittleEndian.AppendUint32(head.data, entries[i].runtimeStartAddr)
// 		head.data = binary.LittleEndian.AppendUint32(head.data, entries[i].sizeOrEnd)
// 	}
// }

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
