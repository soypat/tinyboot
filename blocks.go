package picobin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

//go:generate stringer -type="ImageType,ExeCPU,ExeChip,ExeSec,ItemType" -linecomment -output stringers.go .

// Block delimiters. Are encoded as little endian like all picobin data. They were chosen to be numbers that were very unlikely to appear in ARM machine code.
const (
	BlockMarkerStart = 0xffffded3
	BlockMarkerEnd   = 0xab123579
	minBlockSize     = 4 + 4 + 4 + 4 // Header + last_item + Link + Footer
	maskByteSize2    = 1
)

var (
	startMarker = binary.LittleEndian.AppendUint32(nil, BlockMarkerStart)
	endMarker   = binary.LittleEndian.AppendUint32(nil, BlockMarkerEnd)
)

// Block represents a single valid picobin block in full. It's item list cannot contain the last item type.
type Block struct {
	// Items is a list of items not including the ItemTypeLast item.
	Items []Item
	// Link item specifies relative position in bytes of next block header relative to this block's header.
	// Set to 0 to form loop with self (specifying 1 block)
	Link int
}

// Validate performs all possible static checks on the block and its items for saneness.
func (b Block) Validate() error {
	sz := b.Size()
	if b.Link > math.MaxInt32 || b.Link < math.MinInt32 {
		return errors.New("block link overflows int32")
	} else if b.Link < sz && b.Link > -minBlockSize {
		return errors.New("block link points to memory inside itself or to impossible block")
	}
	expectSz := minBlockSize
	for i := range b.Items {
		if b.Items[i].ItemType() == ItemTypeLast {
			return errors.New("block contains last item type")
		}
		err := b.Items[i].Validate()
		if err != nil {
			return fmt.Errorf("block item %d (%s): %w", i, b.Items[i].String(), err)
		}
		expectSz += len(b.Items[i].Data) + 4
	}
	if sz != expectSz {
		return fmt.Errorf("expected %d size, got %d", expectSz, sz)
	}
	return nil
}

func (b Block) String() string {
	return fmt.Sprintf("%s link=%d", b.Items, b.Link)
}

// Size returns the size of the block in bytes, from start of header to end of footer.
func (b Block) Size() int {
	size := minBlockSize // Header+ItemLast+Link+Footer.
	for i := range b.Items {
		if b.Items[i].ItemType() == ItemTypeLast {
			return -1 // Items should not contain ItemTypeLast
		}
		size += b.Items[i].Size()
	}
	return size
}

// NextBlockIdx returns the start and end indices of the next block by looking for start marker. If only looking for block start
// one can use the following one-liner:
//
//	nextBlockStart := bytes.Index(text, binary.LittleEndian.AppendUint32(nil, picobin.BlockMarkerStart))
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

// DecodeBlock decodes the block at the start of text. It returns amount of bytes read until the end block marker end.
// If the block is malformed it fails to decode and returns error. Note block is not fully validated after being decoded.
// Call [Block.Validate] to ensure block saneness after decoding.
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
	if block.Size() != n {
		return block, n, fmt.Errorf("inconsistency in block size calculation, got %d, want %d", block.Size(), n)
	}
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

// AppendTo appends block to dst without checking data. Call [Block.Validate] before
// AppendTo to ensure data being appended is sane.
func (b Block) AppendTo(dst []byte) []byte {
	dst = binary.LittleEndian.AppendUint32(dst, BlockMarkerStart)
	size := 0
	for i := range b.Items {
		size += b.Items[i].Size()
		header := b.Items[i].HeaderBytes()
		dst = append(dst, header[:]...)
		dst = append(dst, b.Items[i].Data...)
	}
	dst = appendLastItem(dst, size)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(int32(b.Link)))
	dst = binary.LittleEndian.AppendUint32(dst, BlockMarkerEnd)
	return dst
}

func appendLastItem(dst []byte, totalSizeItemsBytes int) []byte {
	item := Item{
		Head:           byte(ItemTypeLast<<1) | maskByteSize2,
		SizeAndSpecial: uint16(totalSizeItemsBytes / 4),
		TypeData:       0, // pad.
	}
	header := item.HeaderBytes()
	dst = append(dst, header[:]...)
	return dst
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
