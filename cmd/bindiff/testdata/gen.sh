#!/bin/sh
# Regenerates the bindiff fixture pair.
#
# blinky-a.elf and blinky-b.elf are two builds of the same program that differ
# by one added function, so a diff between them has a known, small answer:
# checksum and blinkCount inline into main, growing main.main by a few bytes,
# while the debug sections grow by rather more.
#
# The output is checked in rather than built during `go test`, because CI has no
# TinyGo toolchain. Rerun this only when the fixtures need to change, and expect
# the byte counts in bindiff_test.go to move when you do -- they are toolchain
# specific. Generated with:
#
#   tinygo version 0.42.0-dev-c2346570 linux/amd64 (go1.26.4, LLVM 22.1.4)
#
set -eu

# The sources carry their own go.mod so TinyGo resolves them independently of
# the tinyboot module.
cd "$(dirname "$0")/src"

for variant in a b; do
	tinygo build -o "../blinky-$variant.elf" -target=pca10040 "./$variant"
done
cd ..

echo "regenerated:"
ls -l blinky-a.elf blinky-b.elf
