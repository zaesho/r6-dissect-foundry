package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	typeCode uint16
	rawBytes []byte
}

var packets []packet
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capture98)
	r.Read()

	fmt.Printf("Captured %d 0x98xx/0x90xx packets\n\n", len(packets))

	// Analyze 0x9801
	type98 := []packet{}
	type90 := []packet{}
	for _, p := range packets {
		if p.typeCode == 0x9801 {
			type98 = append(type98, p)
		} else if p.typeCode == 0x9001 {
			type90 = append(type90, p)
		}
	}

	fmt.Printf("=== 0x9801 packets (%d) ===\n", len(type98))
	analyzeGroup(type98, 10)

	fmt.Printf("\n=== 0x9001 packets (%d) ===\n", len(type90))
	analyzeGroup(type90, 10)
}

func analyzeGroup(group []packet, showCount int) {
	// Show first N packets
	for i := 0; i < showCount && i < len(group); i++ {
		p := group[i]
		fmt.Printf("\n[%d] Raw: %02X\n", i, p.rawBytes[:40])
		
		// Try to find coordinates
		for offset := 0; offset+12 <= len(p.rawBytes); offset += 4 {
			x := math.Float32frombits(binary.LittleEndian.Uint32(p.rawBytes[offset:offset+4]))
			y := math.Float32frombits(binary.LittleEndian.Uint32(p.rawBytes[offset+4:offset+8]))
			z := math.Float32frombits(binary.LittleEndian.Uint32(p.rawBytes[offset+8:offset+12]))
			
			if isCoord(x) && isCoord(y) && z >= -5 && z <= 15 {
				fmt.Printf("    Coords at offset %d: (%.2f, %.2f, %.2f)\n", offset, x, y, z)
			}
		}
		
		// Try to find small integers that could be player/entity IDs
		fmt.Printf("    Small integers (1-20):")
		for offset := 0; offset+4 <= len(p.rawBytes); offset++ {
			// Try as single byte
			if p.rawBytes[offset] >= 1 && p.rawBytes[offset] <= 20 {
				fmt.Printf(" [byte %d: %d]", offset, p.rawBytes[offset])
			}
		}
		fmt.Println()
	}
	
	// Look for byte patterns that might be entity IDs
	fmt.Printf("\n--- Byte value distribution at each offset ---\n")
	if len(group) > 0 {
		for offset := 0; offset < 20; offset++ {
			valueCounts := make(map[byte]int)
			for _, p := range group {
				if offset < len(p.rawBytes) {
					valueCounts[p.rawBytes[offset]]++
				}
			}
			
			// Show most common values
			fmt.Printf("Offset %2d:", offset)
			for val, count := range valueCounts {
				if count > len(group)/10 { // >10% frequency
					fmt.Printf(" 0x%02X(%d)", val, count)
				}
			}
			fmt.Println()
		}
	}
}

func capture98(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	// Only capture 0x98xx and 0x90xx
	if typeBytes[0] != 0x98 && typeBytes[0] != 0x90 {
		return nil
	}

	rawBytes, err := r.Bytes(60)
	if err != nil {
		return nil
	}

	packets = append(packets, packet{
		typeCode: typeCode,
		rawBytes: rawBytes,
	})

	return nil
}

func isCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100 && (f < -1 || f > 1)
}
