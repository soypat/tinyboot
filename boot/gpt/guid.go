package gpt

import "errors"

// GUID is a globally unique identifier as stored on disk in a GPT header or
// partition entry. The first three fields are stored little-endian; String
// returns the canonical mixed-endian text form.
type GUID [16]byte

// Well-known GPT partition type GUIDs.
var (
	PartitionTypeUnused             = GUID{}
	PartitionTypeEFISystem          = mustGUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
	PartitionTypeBIOSBoot           = mustGUID("21686148-6449-6E6F-744E-656564454649")
	PartitionTypeMicrosoftBasicData = mustGUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
	PartitionTypeLinuxFilesystem    = mustGUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4")
)

// guidByteOrder maps each position of the canonical text form to the on-disk
// byte index it encodes, with -1 marking a dash. The first three fields are
// little-endian on disk, the last two big-endian.
var guidByteOrder = [...]int{3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15}

const hexDigits = "0123456789ABCDEF"

// String returns the canonical text form of the GUID,
// i.e. "C12A7328-F81F-11D2-BA4B-00A0C93EC93B".
func (g GUID) String() string {
	var dst [36]byte
	g.PutString(dst[:])
	return string(dst[:])
}

func (g GUID) PutString(dst []byte) {
	_ = dst[35]
	i := 0
	for _, idx := range guidByteOrder {
		if idx < 0 {
			dst[i] = '-'
			i++
			continue
		}
		dst[i] = hexDigits[g[idx]>>4]
		dst[i+1] = hexDigits[g[idx]&0xF]
		i += 2
	}
}

// GUIDFromString parses the canonical text form of a GUID, the inverse of
// [GUID.String]. Both upper and lower case hex digits are accepted.
func GUIDFromString(s string) (GUID, error) {
	var g GUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return GUID{}, errors.New("guid: bad text format")
	}
	i := 0
	for _, idx := range guidByteOrder {
		if idx < 0 {
			i++
			continue
		}
		hi, ok1 := fromHex(s[i])
		lo, ok2 := fromHex(s[i+1])
		if !ok1 || !ok2 {
			return GUID{}, errors.New("guid: invalid hex digit")
		}
		g[idx] = hi<<4 | lo
		i += 2
	}
	return g, nil
}

func mustGUID(s string) GUID {
	g, err := GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// IsZero reports whether the GUID is all zeros, which marks an unused
// partition entry.
func (g GUID) IsZero() bool {
	return g == GUID{}
}

// PartitionTypeString returns the human readable name of a well-known
// partition type GUID, or "unknown" if the type is not known.
func (g GUID) PartitionTypeString() string {
	switch g {
	case PartitionTypeUnused:
		return "unused"
	case PartitionTypeEFISystem:
		return "EFI System"
	case PartitionTypeBIOSBoot:
		return "BIOS boot"
	case PartitionTypeMicrosoftBasicData:
		return "Microsoft basic data"
	case PartitionTypeLinuxFilesystem:
		return "Linux filesystem"
	}
	return "unknown"
}
