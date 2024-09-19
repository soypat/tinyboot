package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	_ = 1 << (iota * 10)
	kB
	MB
)

const (
	defaultFlashEnd = 0x20000000
	rp2350FamilyID  = 0xe48bff59
)

type Flags struct {
	argSourcename string
	block         int
	readsize      uint
	flashend      uint64
	familyID      uint
}

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var flags Flags
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(output, "\tavailable commands: [elfinfo, elfdump, uf2info]\n")
		fmt.Fprintf(output, "Example:\n\tpicobin info <ELF-filename>\n")
		flag.PrintDefaults()
	}
	flag.IntVar(&flags.block, "block", -1, "Specify a single block to analyze")
	flag.UintVar(&flags.readsize, "readlim", 2*MB, "Size of haystack to look for blocks in, starting at ROM start address")
	flag.Uint64Var(&flags.flashend, "flashend", defaultFlashEnd, "End limit of flash memory. All memory past this limit is ignored.")
	flag.UintVar(&flags.familyID, "familyid", rp2350FamilyID, "Family ID for UF2 generation.")
	flag.Parse()
	command := flag.Arg(0)
	source := flag.Arg(1)
	flags.argSourcename = source
	// First check command argument.
	if command == "" {
		flag.Usage()
		return errors.New("missing command argument")
	}
	var cmd func(io.ReaderAt, Flags) error
	switch command {
	case "elfinfo":
		cmd = elfinfo

	case "elfdump":
		cmd = elfdump

	case "uf2info":
		cmd = uf2info

	case "uf2conv":
		cmd = uf2conv

	default:
		flag.Usage()
		return errors.New("uknown command: " + command)
	}

	// Next check filename.
	if source == "" {
		flag.Usage()
		return errors.New("missing filename argument")
	}
	file, err := os.Open(source)
	// file, err := elf.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()

	// Finally run command.
	return cmd(file, flags)
}
