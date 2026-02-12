package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	data, err := os.ReadFile("samplefiles/nighthaven_R01_dump2.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}

	fmt.Println("=== Checking suffix patterns after marker in Nighthaven ===\n")

	suffixCounts := make(map[string]int)
	
	type example struct {
		offset int
		suffix string
		coords [3]float32
	}
	suffixExamples := make(map[string][]example)

	for i := 0; i <= len(data)-32; i++ {
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

		// Get bytes at offset +12 (after marker + seq)
		suffixStart := i + 8 + 4
		suffix := hex.EncodeToString(data[suffixStart : suffixStart+8])
		suffixCounts[suffix]++

		// Read coords at +20
		floatOff := i + 20
		x := readFloat(data[floatOff:])
		y := readFloat(data[floatOff+4:])
		z := readFloat(data[floatOff+8:])

		if len(suffixExamples[suffix]) < 3 {
			suffixExamples[suffix] = append(suffixExamples[suffix], example{
				i, suffix, [3]float32{x, y, z},
			})
		}
	}

	fmt.Printf("Found %d unique suffix patterns\n\n", len(suffixCounts))

	// Sort by count
	type suffixInfo struct {
		suffix string
		count  int
	}
	var sorted []suffixInfo
	for s, c := range suffixCounts {
		sorted = append(sorted, suffixInfo{s, c})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	fmt.Println("Top suffixes:")
	for i := 0; i < min(10, len(sorted)); i++ {
		s := sorted[i]
		fmt.Printf("\n  Suffix %s: %d occurrences\n", s.suffix, s.count)
		for _, ex := range suffixExamples[s.suffix] {
			fmt.Printf("    @ 0x%06X: (%.2f, %.2f, %.2f)\n", ex.offset, ex.coords[0], ex.coords[1], ex.coords[2])
		}
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
