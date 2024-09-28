package xelf

import "unsafe"

// safechunk is an arbitrary limit on how much memory we are willing
// to allocate without concern.
const safechunk = 10 << 20 // 10M

// sliceCapWithSize returns the capacity to use when allocating a slice.
// After the slice is allocated with the capacity, it should be
// built using append. This will avoid allocating too much memory
// if the capacity is large and incorrect.
//
// A negative result means that the value is always too big.
func sliceCapWithSize(size, c uint64) int {
	if int64(c) < 0 || c != uint64(int(c)) {
		return -1
	}
	if size > 0 && c > (1<<64-1)/size {
		return -1
	}
	if c*size > safechunk {
		c = safechunk / size
		if c == 0 {
			c = 1
		}
	}
	return int(c)
}

// sliceCap is like SliceCapWithSize but using generics.
func sliceCap[E any](c uint64) int {
	var v E
	size := uint64(unsafe.Sizeof(v))
	return sliceCapWithSize(size, c)
}
