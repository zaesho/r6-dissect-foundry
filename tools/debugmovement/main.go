package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	data, err := os.ReadFile("samplefiles/R01_dump.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Look for 00 00 60 73 85 fe
	marker := []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	
	fmt.Println("=== Analyzing player position packet structure ===\n")
	
	count := 0
	for i := 0; i <= len(data)-30; i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		// Read type bytes
		type0 := data[i+6]
		type1 := data[i+7]
		
		// Only show position types (01 or 03 suffix)
		if type1 != 0x01 && type1 != 0x03 {
			continue
		}
		
		// Check for valid coords at offset +8
		if i+8+12 > len(data) {
			continue
		}
		x := readFloat(data[i+8:])
		y := readFloat(data[i+12:])
		z := readFloat(data[i+16:])
		
		// Skip if not world coords
		if x < -100 || x > 100 || y < -50 || y > 50 || z < -5 || z > 15 {
			continue
		}
		if abs(x) < 2 && abs(y) < 2 {
			continue
		}
		
		fmt.Printf("@ 0x%06X: type=%02x%02x\n", i, type0, type1)
		fmt.Printf("  Full packet: %s\n", hex.EncodeToString(data[i:min(i+30, len(data))]))
		
		// Try reading floats at different offsets
		for off := 8; off <= 20; off += 4 {
			if i+off+12 > len(data) {
				continue
			}
			x := readFloat(data[i+off:])
			y := readFloat(data[i+off+4:])
			z := readFloat(data[i+off+8:])
			
			fmt.Printf("  Offset +%d: (%.2f, %.2f, %.2f)\n", off, x, y, z)
		}
		
		count++
		if count >= 10 {
			break
		}
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func abs(f float32) float32 {
	if f < 0 { return -f }
	return f
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
