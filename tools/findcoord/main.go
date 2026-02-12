package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	data, err := os.ReadFile("samplefiles/border_R01_dump.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Searching for real world coordinates in Border ===")
	fmt.Println("Looking for float triplets with X: 70-100, Y: -80 to -50, Z: 3-10\n")

	// These ranges match the Border coordinates we saw
	type coordMatch struct {
		offset int
		x, y, z float32
	}
	
	var matches []coordMatch

	for i := 0; i < len(data)-12; i++ {
		x := readFloat(data[i:])
		y := readFloat(data[i+4:])
		z := readFloat(data[i+8:])

		// Look for Border-like coordinates
		if x >= 70 && x <= 100 &&
		   y >= -80 && y <= -50 &&
		   z >= 3 && z <= 10 {
			matches = append(matches, coordMatch{i, x, y, z})
		}
	}

	fmt.Printf("Found %d coordinate triplets in expected range\n\n", len(matches))

	// Group by similar coordinates to find distinct positions
	fmt.Println("First 50 matches with context:")
	for i := 0; i < min(50, len(matches)); i++ {
		m := matches[i]
		
		// Show 20 bytes before
		start := m.offset - 20
		if start < 0 {
			start = 0
		}
		
		fmt.Printf("=== Offset 0x%06X: (%.2f, %.2f, %.2f) ===\n", m.offset, m.x, m.y, m.z)
		fmt.Printf("  Before: %s\n", hex.EncodeToString(data[start:m.offset]))
		fmt.Printf("  Floats: %s\n", hex.EncodeToString(data[m.offset:m.offset+12]))
		
		// Check bytes after
		end := m.offset + 20
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("  After:  %s\n\n", hex.EncodeToString(data[m.offset+12:end]))
	}

	// Look for patterns in the "before" bytes
	fmt.Println("\n=== Analyzing common prefixes ===")
	prefixCounts := make(map[string]int)
	for _, m := range matches {
		if m.offset >= 8 {
			prefix := hex.EncodeToString(data[m.offset-8 : m.offset])
			prefixCounts[prefix]++
		}
	}
	
	type prefixInfo struct {
		prefix string
		count  int
	}
	var sortedPrefixes []prefixInfo
	for p, c := range prefixCounts {
		if c >= 10 {
			sortedPrefixes = append(sortedPrefixes, prefixInfo{p, c})
		}
	}
	
	// Sort by count
	for i := 0; i < len(sortedPrefixes)-1; i++ {
		for j := i + 1; j < len(sortedPrefixes); j++ {
			if sortedPrefixes[j].count > sortedPrefixes[i].count {
				sortedPrefixes[i], sortedPrefixes[j] = sortedPrefixes[j], sortedPrefixes[i]
			}
		}
	}
	
	fmt.Printf("Top prefixes (8 bytes before coordinates):\n")
	for i := 0; i < min(20, len(sortedPrefixes)); i++ {
		p := sortedPrefixes[i]
		fmt.Printf("  %s: %d times\n", p.prefix, p.count)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
