# tinyboot
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/tinyboot)](https://pkg.go.dev/github.com/soypat/tinyboot)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/tinyboot)](https://goreportcard.com/report/github.com/soypat/tinyboot)
[![codecov](https://codecov.io/gh/soypat/tinyboot/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/tinyboot)
[![Go](https://github.com/soypat/tinyboot/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/tinyboot/actions/workflows/go.yml)

Tools for working with program builds and bootable partitions.

How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/tinyboot@latest
```

## Package layout
There are two main top level packages:
- [`boot`](./boot): Concerns storage formats for booting a computer such as MBT, GPT and Raspberry Pi's picobin format.
    - [`boot/mbt`](./boot/mbt): Master Boot Record Partition Table interfacing.
    - [`boot/gpt`](./boot/gpt): GUID Partition Table interfacing.
    - [`boot/picobin`](./boot/picobin): Raspberry Pi's bootable format for RP2350 and RP2040.

- [`build`](./build): Concerns manipulation of computer program formats such as ELF and UF2.
    - [`build/elfutil`](./build/elfutil): Manipulation of ELF files that works on top of `debug/elf` standard library package.
    - [`build/uf2`](./build/uf2): Manipulation of Microsoft's UF2 format

## picobin tool
picobin tool permits users to inspect RP2350 and RP2040 binaries which are structured according to Raspberry Pi's picobin format.
