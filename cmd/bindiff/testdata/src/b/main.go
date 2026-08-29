package main

import (
	"machine"
	"time"
)

// checksum is the payload that makes build "b" bigger than build "a".
func checksum(data []byte) uint32 {
	var sum uint32
	for _, c := range data {
		sum = sum<<3 | sum>>29
		sum += uint32(c)
	}
	return sum
}

func blinkCount(sum uint32) int {
	return int(sum%4) + 1
}

func main() {
	led := machine.LED
	led.Configure(machine.PinConfig{Mode: machine.PinOutput})
	buf := []byte("tinyboot bindiff fixture")
	for {
		n := blinkCount(checksum(buf))
		for i := 0; i < n; i++ {
			led.Low()
			time.Sleep(300 * time.Millisecond)
			led.High()
			time.Sleep(300 * time.Millisecond)
		}
	}
}
