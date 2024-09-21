package uf2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

var (
	errSmallBlock = errors.New("buffer too small to contain block")
	errMagic0     = errors.New("first word is not magic0 word \"UF2\\n\"")
	errMagic1     = errors.New("second word is not magic1 word")
	errMagicEnd   = errors.New("last word is not magic end word")
)

const (
	BlockSize       = 512
	MagicStart0     = 0x0A324655 // "UF2\n"
	MagicStart1     = 0x9E5D5157 // Randomly selected
	MagicEnd        = 0x0AB16F30 // Also randomly selected.
	BlockMaxData    = 476
	defaultDataSize = 256
)

// Block is the structure used for each UF2 code block sent to device. It is 512 bytes in size. Size of header is 32 bytes.
type Block struct {
	Flags          Flags
	TargetAddr     uint32 // Address in flash where the data should be written.
	PayloadSize    uint32 // Number of byttes used in data (often 256).
	BlockNum       uint32 // Sequential block number; starts at 0.
	NumBlocks      uint32 // Total number of blocks in file.
	SizeOrFamilyID uint32 // File size or board familyID or zero
	RawData        [BlockMaxData]byte
}

type Flags uint32

const (
	FlagNotMainFlash         Flags = 1 << 0
	FlagFamilyIDPresent      Flags = 1 << 13
	FlagFileContainer        Flags = 1 << 12
	FlagMD5ChecksumPresent   Flags = 1 << 14
	FlagExtensionTagsPresent Flags = 1 << 15
)

// AppendTo appends the blocks' binary representation to the argument buffer and returns the result, including magic start and end.
// It performs no error checking.
func (b Block) AppendTo(dst []byte) []byte {
	hd := b.HeaderBytes()
	dst = append(dst, hd[:]...)
	dst = append(dst, b.RawData[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, MagicEnd)
	return dst
}

func (block Block) String() string {
	if block.Flags&FlagFamilyIDPresent != 0 {
		return fmt.Sprintf("Block %2d/%2d flags=%#x size=%d family=%#x addr=%#x", block.BlockNum+1, block.NumBlocks, block.Flags, block.PayloadSize, block.SizeOrFamilyID, block.TargetAddr)
	}
	return fmt.Sprintf("Block %2d/%2d flags=%#x size=%d/%d addr=%#x", block.BlockNum+1, block.NumBlocks, block.Flags, block.PayloadSize, block.SizeOrFamilyID, block.TargetAddr)
}

// HeaderBytes returns the block's HeaderBytes.
func (b Block) HeaderBytes() (hd [32]byte) {
	binary.LittleEndian.PutUint32(hd[0:], MagicStart0)
	binary.LittleEndian.PutUint32(hd[4:], MagicStart1)
	binary.LittleEndian.PutUint32(hd[8:], uint32(b.Flags))
	binary.LittleEndian.PutUint32(hd[12:], b.TargetAddr)
	binary.LittleEndian.PutUint32(hd[16:], b.PayloadSize)
	binary.LittleEndian.PutUint32(hd[20:], b.BlockNum)
	binary.LittleEndian.PutUint32(hd[24:], b.NumBlocks)
	binary.LittleEndian.PutUint32(hd[28:], b.SizeOrFamilyID)
	return hd
}

// Data returns a pointer to this block's data field limited to the payload size it has.
func (b *Block) Data() ([]byte, error) {
	err := b.Validate()
	if err != nil {
		return nil, err
	}
	return b.RawData[:b.PayloadSize], nil
}

// Validate checks block fields for inconsistencies.
func (b *Block) Validate() error {
	sz := b.PayloadSize
	if sz > BlockMaxData {
		return errors.New("payload size exeeds permissible maximum")
	} else if sz == 0 {
		return errors.New("zero payload size")
	}
	return nil
}

func DecodeAppendBlocks(dst []Block, r io.Reader, buf []byte) ([]Block, int, error) {
	if len(buf) < BlockSize {
		return dst, 0, errors.New("decode buffer to small to fit a block")
	}
	// Round size of buffer to block size.
	buf = buf[:len(buf)-len(buf)%BlockSize]
	ntot := 0
	numBlocks := 0
	for {
		n, err := io.ReadFull(r, buf)
		ntot += n
		i := 0
		for i+BlockSize <= n {
			block, err := DecodeBlock(buf[i:])
			if err != nil {
				return dst, ntot, err
			}
			dst = append(dst, block)
			i += BlockSize
			numBlocks++
		}
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				err = nil
			}
			return dst, ntot, err
		}
	}
}

// DecodeBlock decodes a 512 byte block from the argument buffer. Buffer must be at least 512 bytes long.
func DecodeBlock(text []byte) (Block, error) {
	err := ValidateBlock(text)
	if err != nil {
		return Block{}, err
	}
	block := MustDecodeBlock(text)
	return block, nil
}

// MustDecodeBlock attempts to decode 512 byte block without bounds checking. Panics if buffer is shorter than 512 bytes.
func MustDecodeBlock(text []byte) (block Block) {
	_ = text[511]
	block.Flags = Flags(binary.LittleEndian.Uint32(text[8:]))
	block.TargetAddr = binary.LittleEndian.Uint32(text[12:])
	block.PayloadSize = binary.LittleEndian.Uint32(text[16:])
	block.BlockNum = binary.LittleEndian.Uint32(text[20:])
	block.NumBlocks = binary.LittleEndian.Uint32(text[24:])
	block.SizeOrFamilyID = binary.LittleEndian.Uint32(text[28:])
	copy(block.RawData[:], text[32:])
	return block
}

func ValidateBlock(text []byte) error {
	if len(text) < 512 {
		return errSmallBlock
	}
	gotMagic0 := binary.LittleEndian.Uint32(text[0:])
	gotMagic1 := binary.LittleEndian.Uint32(text[4:])
	gotMagicEnd := binary.LittleEndian.Uint32(text[512-4:])
	var err error
	if gotMagic0 != MagicStart0 {
		err = errMagic0
	} else if gotMagic1 != MagicStart1 {
		err = errMagic1
	} else if gotMagicEnd != MagicEnd {
		err = errMagicEnd
	}
	return err
}

type Formatter struct {
	Flags     Flags
	FamilyID  uint32
	ChunkSize uint32 // How to chunk payload (is payload size field). By default is chosen as 256. Maximum is 476.
}

func (f *Formatter) SetFamilyID(familyID string) error {
	v, err := strconv.ParseUint(familyID, 0, 32)
	if err != nil {
		return err
	} else if v > math.MaxUint32 {
		return errors.New("family ID overflows uint32")
	}
	f.FamilyID = uint32(v)
	f.Flags |= FlagFamilyIDPresent
	return nil
}

func (f *Formatter) startBlock(datalen int, targetAddr uint32) (Block, error) {
	if f.ChunkSize > BlockMaxData {
		return Block{}, errors.New("chunk size too large")
	} else if f.ChunkSize == 0 {
		f.ChunkSize = 256 // Default value.
	}
	var familyOrSize uint32
	if f.Flags&FlagFamilyIDPresent != 0 {
		familyOrSize = f.FamilyID
	} else {
		if datalen > math.MaxUint32 {
			return Block{}, errors.New("data length overflows uint32, use familyID to omit size field")
		}
		familyOrSize = uint32(datalen)
	}
	numBlocks := datalen / int(f.ChunkSize)
	excedent := datalen % int(f.ChunkSize)
	if excedent != 0 {
		numBlocks++
	} else if numBlocks > math.MaxUint32 {
		return Block{}, errors.New("number of UF2 blocks overflows uint32")
	}
	block := Block{
		Flags:          f.Flags,
		TargetAddr:     targetAddr,
		PayloadSize:    f.ChunkSize,
		BlockNum:       0,
		NumBlocks:      uint32(numBlocks),
		SizeOrFamilyID: familyOrSize,
	}
	return block, nil
}

// AppendTo appends data formatted as UF2 blocks to dst and returns the result and number of blocks written.
// To get total size appended one can do blocksWritten*512.
func (f *Formatter) AppendTo(dst, data []byte, targetAddr uint32) (uftFormatted []byte, blocksWritten int, err error) {
	blocks := 0
	err = f.forEachBlock(data, targetAddr, func(b Block) error {
		blocks++
		dst = b.AppendTo(dst)
		return nil
	})
	if err != nil {
		return dst, blocks, err
	}
	return dst, blocks, nil
}

func (f *Formatter) forEachBlock(data []byte, targetAddr uint32, fn func(Block) error) error {
	block, err := f.startBlock(len(data), targetAddr)
	if err != nil {
		return err
	}
	remaining := block.NumBlocks
	maxPayload := block.PayloadSize
	dataOff := 0
	for remaining > 0 {
		block.PayloadSize = uint32(copy(block.RawData[:maxPayload], data[dataOff:]))
		oob := block.RawData[block.PayloadSize:]
		for i := range oob {
			oob[i] = 0 // Clear memory out of bounds.
		}
		err = fn(block)
		if err != nil {
			return err
		}
		dataOff += int(block.PayloadSize)
		block.TargetAddr += block.PayloadSize
		block.BlockNum++
		remaining--
	}
	return nil
}

func NewBlocksReaderAt(blocks []Block) (*BlocksReaderAt, error) {
	obj := BlocksReaderAt{
		blks:    blocks,
		minAddr: 0xffff_ffff,
	}
	for i := range blocks {
		err := blocks[i].Validate()
		if err != nil {
			return nil, err
		}
		obj.minAddr = min(obj.minAddr, blocks[i].TargetAddr)
		obj.maxAddr = max(obj.maxAddr, blocks[i].TargetAddr+blocks[i].PayloadSize)
	}
	return &obj, nil
}

type BlocksReaderAt struct {
	blks             []Block
	minAddr, maxAddr uint32
}

func (blks *BlocksReaderAt) Addrs() (start, end uint32) {
	return blks.minAddr, blks.maxAddr
}

func (blks *BlocksReaderAt) ReadAt(b []byte, addr int64) (int, error) {
	blocks := blks.blks
	end := addr + int64(len(b))
	if !aliases(addr, end, int64(blks.minAddr), int64(blks.maxAddr)) {
		return 0, io.EOF
	}
	clear(b)
	maxRead := 0
	for i := range blocks {
		blkAddr := int64(blocks[i].TargetAddr)
		blkEnd := blkAddr + int64(blocks[i].PayloadSize)
		if !aliases(addr, end, blkAddr, blkEnd) {
			continue
		}
		// progOff := max(0, addr-blkAddr)
		bOff := max(0, blkAddr-addr)
		n := copy(b[bOff:], blocks[i].RawData[:blocks[i].PayloadSize])
		maxRead = int(bOff) + n
	}
	return maxRead, nil
}

func aliases(start0, end0, start1, end1 int64) bool {
	return start0 < end1 && end0 > start1
}

func max[T ~int | ~int64 | ~uint32 | ~uint64](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T ~int | ~int64 | ~uint32 | ~uint64](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func clear[E any](a []E) {
	var z E
	for i := range a {
		a[i] = z
	}
}
