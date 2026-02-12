package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

// What if each packet contains MULTIPLE player positions?
// Let's look for repeating coordinate patterns within packets

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

	// Capture raw packets with lots of data
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureRaw)
	r.Read()

	fmt.Printf("Captured %d packets\n\n", len(packets))

	// Look at B803 packets - search for MULTIPLE coordinate triplets within each packet
	var b803 []rawPacket
	for _, p := range packets {
		if p.typeCode == 0xB803 {
			b803 = append(b803, p)
		}
	}

	fmt.Printf("Analyzing %d B803 packets for multiple position data\n\n", len(b803))

	// For a sample of packets, find ALL valid coordinate triplets
	for i := 0; i < 10 && i < len(b803); i++ {
		p := b803[i]
		fmt.Printf("\n=== Packet %d (total %d bytes) ===\n", i, len(p.allBytes))
		fmt.Printf("Raw: %02X\n", p.allBytes[:60])

		// Search for coordinate triplets at all offsets
		fmt.Printf("Valid coordinate triplets found:\n")
		found := 0
		for offset := 0; offset+12 <= len(p.allBytes); offset += 4 {
			x := math.Float32frombits(binary.LittleEndian.Uint32(p.allBytes[offset : offset+4]))
			y := math.Float32frombits(binary.LittleEndian.Uint32(p.allBytes[offset+4 : offset+8]))
			z := math.Float32frombits(binary.LittleEndian.Uint32(p.allBytes[offset+8 : offset+12]))

			if isValidCoord(x) && isValidCoord(y) && isValidZ(z) {
				fmt.Printf("  Offset %2d: (%.2f, %.2f, %.2f)\n", offset, x, y, z)
				found++
			}
		}
		fmt.Printf("  Total valid triplets: %d\n", found)
	}

	// Now check: how many DISTINCT coordinate triplets exist across ALL B803 packets?
	// If each packet has the same positions for all players, we should see ~10 unique positions per moment
	fmt.Printf("\n\n=== Checking for batched player positions ===\n")
	
	// Group consecutive packets and see if they contain ~10 different positions
	windowSize := 20 // Check 20 consecutive packets
	for windowStart := 0; windowStart+windowSize <= len(b803) && windowStart < 100; windowStart += windowSize {
		positionSet := make(map[string]int)
		
		for i := windowStart; i < windowStart+windowSize; i++ {
			p := b803[i]
			// Get the first coordinate triplet (offset 0)
			if len(p.allBytes) >= 12 {
				x := math.Float32frombits(binary.LittleEndian.Uint32(p.allBytes[0:4]))
				y := math.Float32frombits(binary.LittleEndian.Uint32(p.allBytes[4:8]))
				
				if isValidCoord(x) && isValidCoord(y) {
					key := fmt.Sprintf("%.1f,%.1f", x, y)
					positionSet[key]++
				}
			}
		}
		
		fmt.Printf("Window %d-%d: %d distinct XY positions\n", windowStart, windowStart+windowSize, len(positionSet))
	}

	// Check if packets come in bursts of 10 (one per player)
	fmt.Printf("\n=== Checking packet timing patterns ===\n")
	
	// Look at packet numbers to see if they come in groups
	if len(b803) > 100 {
		fmt.Printf("First 50 packet numbers:\n")
		for i := 0; i < 50; i++ {
			if i > 0 && b803[i].packetNum - b803[i-1].packetNum > 5 {
				fmt.Print(" | ")
			}
			fmt.Printf("%d ", b803[i].packetNum)
		}
		fmt.Println()
	}
}

func captureRaw(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	// Read lots of bytes
	allBytes, err := r.Bytes(120)
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
