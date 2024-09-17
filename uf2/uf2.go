package uf2

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
)

const (
	MagicStart0         = 0x0A324655 // "UF2\n"
	MagicStart1         = 0x9E5D5157 // Randomly selected
	MagicEnd            = 0x0AB16F30 // Also randomly selected.
	flagFamilyIDPresent = 0x00002000
)

var magicStart = binary.LittleEndian.AppendUint32(
	binary.LittleEndian.AppendUint32(nil, MagicStart0),
	MagicStart1,
)

// Block is the structure used for each UF2 code block sent to device.
type Block struct {
	Flags       uint32
	TargetAddr  uint32
	PayloadSize uint32
	BlockNum    uint32
	NumBlocks   uint32
	FamilyID    uint32
	Data        [476]byte
}

func NewBlockFromFamilyID(targetAddr uint32, uf2FamilyID string) (blk Block, err error) {
	var familyID uint32
	var flags uint32
	if uf2FamilyID != "" {
		flags |= flagFamilyIDPresent
		v, err := strconv.ParseUint(uf2FamilyID, 0, 32)
		if err != nil {
			return Block{}, err
		} else if v > math.MaxUint32 {
			return Block{}, errors.New("familyID overflows uint32")
		}
		familyID = uint32(v)
	}
	return Block{
		TargetAddr:  targetAddr,
		Flags:       flags,
		FamilyID:    familyID,
		PayloadSize: 256,
	}, nil
}

// AppendTo appends the blocks' binary representation to the argument buffer and returns the result, including magic start and end.
// It performs no error checking.
func (b Block) AppendTo(dst []byte) []byte {
	dst = append(dst, magicStart...)
	dst = binary.LittleEndian.AppendUint32(dst, b.TargetAddr)
	dst = binary.LittleEndian.AppendUint32(dst, b.PayloadSize)
	dst = binary.LittleEndian.AppendUint32(dst, b.BlockNum)
	dst = binary.LittleEndian.AppendUint32(dst, b.NumBlocks)
	dst = binary.LittleEndian.AppendUint32(dst, b.FamilyID)
	dst = append(dst, b.Data[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, MagicEnd)
	return dst
}
