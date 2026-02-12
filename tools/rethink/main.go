package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

// Let's look at the FULL packet structure more carefully
// Maybe what we thought was "player ID" is actually something else

type rawPacket struct {
	typeCode  uint16
	packetNum int
	allBytes  []byte // Raw bytes after type code
}

var packets []rawPacket
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureRaw)
	r.Read()

	fmt.Printf("Total packets: %d\n\n", len(packets))

	// Let's examine the structure differently
	// For B8 03 type packets, let's look at what's BEFORE the coordinates
	// and see if there's a pattern that correlates with 10 distinct entities

	fmt.Printf("=== Analyzing B803 packet structure in detail ===\n\n")
	
	var b803 []rawPacket
	for _, p := range packets {
		if p.typeCode == 0xB803 {
			b803 = append(b803, p)
		}
	}
	
	fmt.Printf("B803 packets: %d\n\n", len(b803))

	// Look at EVERY byte position and see which positions have exactly 10 distinct values
	fmt.Printf("Searching for byte positions with exactly 10 distinct values (for 10 players):\n")
	
	for byteOffset := 0; byteOffset < 40; byteOffset++ {
		distinctValues := make(map[byte]int)
		for _, p := range b803 {
			if byteOffset < len(p.allBytes) {
				distinctValues[p.allBytes[byteOffset]]++
			}
		}
		
		// Check if this position has between 8-12 distinct values (roughly 10 players)
		if len(distinctValues) >= 8 && len(distinctValues) <= 15 {
			fmt.Printf("\nOffset %d: %d distinct values\n", byteOffset, len(distinctValues))
			for val, count := range distinctValues {
				fmt.Printf("  0x%02X (%3d): %5d packets\n", val, val, count)
			}
		}
	}

	// Also try 2-byte and 4-byte windows
	fmt.Printf("\n\n=== Checking 4-byte windows for ~10 distinct uint32 values ===\n")
	for offset := 0; offset < 36; offset += 2 {
		distinctU32 := make(map[uint32]int)
		for _, p := range b803 {
			if offset+4 <= len(p.allBytes) {
				val := binary.LittleEndian.Uint32(p.allBytes[offset : offset+4])
				// Only count if value is in a reasonable range
				if val > 0 && val < 100 {
					distinctU32[val]++
				}
			}
		}
		
		if len(distinctU32) >= 8 && len(distinctU32) <= 15 {
			total := 0
			for _, c := range distinctU32 {
				total += c
			}
			fmt.Printf("\nOffset %d: %d distinct values (total %d packets)\n", offset, len(distinctU32), total)
			for val, count := range distinctU32 {
				pct := float64(count) / float64(total) * 100
				fmt.Printf("  %2d: %5d packets (%.1f%%)\n", val, count, pct)
			}
		}
	}

	// Show raw packets at different times to see structure
	fmt.Printf("\n\n=== Sample B803 packets from different parts of the file ===\n")
	indices := []int{0, 1, len(b803)/4, len(b803)/2, 3*len(b803)/4, len(b803)-2, len(b803)-1}
	for _, idx := range indices {
		if idx >= 0 && idx < len(b803) {
			p := b803[idx]
			fmt.Printf("\n[%d] Packet #%d:\n", idx, p.packetNum)
			fmt.Printf("  Bytes 0-39: %02X\n", p.allBytes[:40])
		}
	}
}

func captureRaw(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	// Capture raw bytes
	allBytes, err := r.Bytes(60)
	if err != nil {
		return nil
	}

	packets = append(packets, rawPacket{
		typeCode:  typeCode,
		packetNum: packetNum,
		allBytes:  allBytes,
	})

	return nil
}
