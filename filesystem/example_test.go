package filesystem_test

import (
	"fmt"
	"io"
	"os"

	"github.com/soypat/fat"
	"github.com/soypat/tinyboot/filesystem"
	"github.com/soypat/tinyboot/filesystem/fsfuzz"
)

func ExampleNewFAT() {
	// The device could be an SD card, flash, or anything implementing
	// fat.BlockDevice. Here it is RAM. FAT32 is defined by cluster count, not by
	// a boot-sector field: 66600 sectors of 512 bytes is the smallest volume
	// that formats as FAT32 rather than silently becoming FAT16.
	const sectorSize, sectors = 512, 66600
	device := fsfuzz.NewRAM(sectorSize, sectors)
	var fmtr fat.Formatter
	err := fmtr.Format(device, sectorSize, sectors, fat.FormatParams{Format: fat.FormatFAT32})
	if err != nil {
		panic(err)
	}

	var fatfs filesystem.FATFS
	if err = fatfs.Mount(device, sectorSize, fat.ModeRW); err != nil {
		panic(err)
	}
	// NewFAT wraps the mounted backend with handle pools: opening a file
	// allocates only until the pool has seen the peak number of live handles,
	// and the flags are os.OpenFile flags rather than fat's.
	fsys := filesystem.NewFAT(&fatfs)

	if err = fsys.Mkdir("/logs"); err != nil {
		panic(err)
	}
	f, err := fsys.Create("/logs/boot.txt")
	if err != nil {
		panic(err)
	}
	if _, err = f.WriteString("tinyboot v1\n"); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}

	// O_APPEND is POSIX append: every write goes to the end of the file, and
	// reads are unaffected.
	f, err = fsys.OpenFile("/logs/boot.txt", os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		panic(err)
	}
	if _, err = f.WriteString("fs mounted\n"); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}

	f, err = fsys.Open("/logs/boot.txt")
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	f.Close()
	fmt.Print(string(data))

	// ForEachFile lists a directory without allocating per entry;
	// Dir.ReadNext is the allocating alternative.
	d, err := fsys.OpenDir("/logs")
	if err != nil {
		panic(err)
	}
	defer d.Close()
	err = d.ForEachFile(func(info filesystem.FileInfo) error {
		fmt.Printf("%s %d bytes\n", info.Name(), info.Size())
		return nil
	})
	if err != nil {
		panic(err)
	}
	// Output:
	// tinyboot v1
	// fs mounted
	// boot.txt 23 bytes
}
