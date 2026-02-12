package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	files := []struct {
		path string
		name string
	}{
		{"samplefiles/R01_dump.bin", "Chalet"},
		{"samplefiles/nighthaven_R01_dump.bin", "Nighthaven"},
		{"samplefiles/border_R01_dump.bin", "Border"},
	}

	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", f.path, err)
			continue
		}

		fmt.Printf("\n=== %s (%d bytes) ===\n", f.name, len(data))
		
		// Search for pattern: 83 00 00 00 62 73 85 fe XX XX XX XX 5e 00 00 00 00 00 00 00 [floats]
		// Where XX XX XX XX is a variable sequence number
		findMovementPattern(data, f.name)
	}
}

func findMovementPattern(data []byte, mapName string) {
	// Pattern: 83 00 00 00 62 73 85 fe [4 bytes seq] 5e 00 00 00 00 00 00 00 [12 bytes xyz]
	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}
	suffix := []byte{0x5e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	
	type position struct {
		offset int
		seq    uint32
		x, y, z float32
	}
	
	var positions []position
	
	for i := 0; i <= len(data)-32; i++ {
		// Check for marker
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
		
		// Check for suffix at offset +12 (marker=8, seq=4, suffix=8)
		suffixOff := i + 8 + 4
		for j, b := range suffix {
			if data[suffixOff+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		// Read sequence number
		seq := binary.LittleEndian.Uint32(data[i+8:])
		
		// Read position floats (at offset +20 from start)
		floatOff := i + 20
		x := readFloat(data[floatOff:])
		y := readFloat(data[floatOff+4:])
		z := readFloat(data[floatOff+8:])
		
		// Validate coordinates are reasonable
		if isValidCoord(x) && isValidCoord(y) && isValidCoord(z) {
			positions = append(positions, position{i, seq, x, y, z})
		}
	}
	
	fmt.Printf("Found %d position packets with pattern 83000000627385fe...5e00000000000000\n", len(positions))
	
	if len(positions) > 0 {
		fmt.Println("\nFirst 20 positions:")
		for i := 0; i < min(20, len(positions)); i++ {
			p := positions[i]
			fmt.Printf("  Seq 0x%08X @ 0x%06X: (%.2f, %.2f, %.2f)\n", p.seq, p.offset, p.x, p.y, p.z)
		}
		
		fmt.Println("\nLast 20 positions:")
		start := len(positions) - 20
		if start < 0 {
			start = 0
		}
		for i := start; i < len(positions); i++ {
			p := positions[i]
			fmt.Printf("  Seq 0x%08X @ 0x%06X: (%.2f, %.2f, %.2f)\n", p.seq, p.offset, p.x, p.y, p.z)
		}
		
		// Analyze coordinate ranges
		var minX, maxX, minY, maxY, minZ, maxZ float32 = 999, -999, 999, -999, 999, -999
		for _, p := range positions {
			if p.x < minX { minX = p.x }
			if p.x > maxX { maxX = p.x }
			if p.y < minY { minY = p.y }
			if p.y > maxY { maxY = p.y }
			if p.z < minZ { minZ = p.z }
			if p.z > maxZ { maxZ = p.z }
		}
		fmt.Printf("\nCoordinate ranges:\n")
		fmt.Printf("  X: %.2f to %.2f\n", minX, maxX)
		fmt.Printf("  Y: %.2f to %.2f\n", minY, maxY)
		fmt.Printf("  Z: %.2f to %.2f\n", minZ, maxZ)
	}
	
	// Also try other variants of the pattern
	fmt.Println("\n--- Trying alternate patterns ---")
	
	// Try just "60 73 85 fe" variant
	altMarkers := [][]byte{
		{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe},
		{0x00, 0x00, 0x00, 0x60, 0x73, 0x85, 0xfe},
	}
	
	for _, altMarker := range altMarkers {
		count := 0
		for i := 0; i <= len(data)-len(altMarker); i++ {
			match := true
			for j, b := range altMarker {
				if data[i+j] != b {
					match = false
					break
				}
			}
			if match {
				count++
			}
		}
		fmt.Printf("Pattern %s: %d occurrences\n", hex.EncodeToString(altMarker), count)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isValidCoord(f float32) bool {
	if f != f { // NaN
		return false
	}
	if math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -200 && f <= 200
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
