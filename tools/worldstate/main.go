package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// Look for packets that might contain multiple (10) coordinate triplets
// This could be a "world state" packet that updates all players at once

type rawPacket struct {
	typeCode  uint16
	packetNum int
	allBytes  []byte
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

	fmt.Printf("Captured %d packets\n\n", len(packets))

	// Group by type and find types with large packets that could hold 10 positions
	// 10 players * 12 bytes (X,Y,Z) = 120 bytes minimum
	typeGroups := make(map[uint16][]rawPacket)
	for _, p := range packets {
		typeGroups[p.typeCode] = append(typeGroups[p.typeCode], p)
	}

	fmt.Printf("=== Looking for packet types that might contain multiple player positions ===\n\n")

	var typeCodes []uint16
	for tc := range typeGroups {
		typeCodes = append(typeCodes, tc)
	}
	sort.Slice(typeCodes, func(i, j int) bool {
		return len(typeGroups[typeCodes[i]]) > len(typeGroups[typeCodes[j]])
	})

	for _, tc := range typeCodes {
		group := typeGroups[tc]
		if len(group) < 100 {
			continue
		}

		// Count how many valid coordinate triplets each packet contains
		totalTriplets := 0
		for _, p := range group {
			triplets := countValidTriplets(p.allBytes)
			totalTriplets += triplets
		}

		avgTriplets := float64(totalTriplets) / float64(len(group))
		if avgTriplets >= 2.0 { // Looking for packets with multiple positions
			fmt.Printf("Type 0x%04X: %d packets, avg %.1f valid triplets/packet\n", tc, len(group), avgTriplets)
		}
	}

	// Also look for packets that cycle through 10 different positions
	// by checking if consecutive packets have different positions
	fmt.Printf("\n=== Checking if certain packet types cycle through 10 unique positions ===\n")

	for _, tc := range typeCodes {
		group := typeGroups[tc]
		if len(group) < 200 {
			continue
		}

		// Check first 100 packets
		posSet := make(map[string]bool)
		for i := 0; i < 100 && i < len(group); i++ {
			p := group[i]
			if len(p.allBytes) >= 12 {
				x := readFloat(p.allBytes[0:4])
				y := readFloat(p.allBytes[4:8])
				if isValidCoord(x) && isValidCoord(y) {
					key := fmt.Sprintf("%.1f,%.1f", x, y)
					posSet[key] = true
				}
			}
		}

		if len(posSet) >= 8 && len(posSet) <= 15 {
			fmt.Printf("Type 0x%04X (%d packets): First 100 have %d distinct XY positions\n", tc, len(group), len(posSet))
		}
	}

	// Check the specific B8xx types for patterns
	fmt.Printf("\n=== Detailed analysis of position packet types ===\n")
	for _, tc := range []uint16{0xB801, 0xB802, 0xB803, 0xB804, 0xB805, 0xB806, 0xB807, 0xB808} {
		group := typeGroups[tc]
		if len(group) == 0 {
			continue
		}

		// Check distribution of small integers at various offsets
		fmt.Printf("\nType 0x%04X (%d packets):\n", tc, len(group))
		
		// Show first 5 packets
		for i := 0; i < 5 && i < len(group); i++ {
			p := group[i]
			x := readFloat(p.allBytes[0:4])
			y := readFloat(p.allBytes[4:8])
			z := readFloat(p.allBytes[8:12])
			fmt.Printf("  [%d] pos=(%.1f, %.1f, %.1f) bytes[32:36]=%d\n", 
				i, x, y, z, binary.LittleEndian.Uint32(p.allBytes[32:36]))
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

	allBytes, err := r.Bytes(150)
	if err != nil {
		allBytes = make([]byte, 0)
	}

	packets = append(packets, rawPacket{
		typeCode:  typeCode,
		packetNum: packetNum,
		allBytes:  allBytes,
	})

	return nil
}

func countValidTriplets(data []byte) int {
	count := 0
	for offset := 0; offset+12 <= len(data); offset += 4 {
		x := readFloat(data[offset : offset+4])
		y := readFloat(data[offset+4 : offset+8])
		z := readFloat(data[offset+8 : offset+12])
		if isValidCoord(x) && isValidCoord(y) && isValidZ(z) {
			count++
		}
	}
	return count
}

func readFloat(b []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(b))
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100 && (f < -1 || f > 1)
}

func isValidZ(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -10 && f <= 50
}
