package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	data, err := os.ReadFile("samplefiles/nighthaven_R01_dump.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Analyzing Nighthaven for position packet variants ===\n")

	// Find all occurrences of "607385fe" and analyze what comes before/after
	marker := []byte{0x60, 0x73, 0x85, 0xfe}
	
	type occurrence struct {
		offset int
		before [16]byte
		after  [32]byte
	}
	
	var occurrences []occurrence
	
	for i := 16; i <= len(data)-36; i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			var occ occurrence
			occ.offset = i
			copy(occ.before[:], data[i-16:i])
			copy(occ.after[:], data[i+4:i+36])
			occurrences = append(occurrences, occ)
			
			if len(occurrences) >= 100000 {
				break // Sample limit
			}
		}
	}
	
	fmt.Printf("Found %d occurrences of 607385fe\n", len(occurrences))

	// Analyze what byte comes right before marker
	prefixCounts := make(map[byte]int)
	for _, occ := range occurrences {
		prefixCounts[occ.before[15]]++
	}
	
	fmt.Println("\nByte immediately before 607385fe:")
	for b, c := range prefixCounts {
		fmt.Printf("  0x%02X: %d occurrences\n", b, c)
	}
	
	// For each prefix type, show first few examples with coordinates
	fmt.Println("\n--- Examples for each prefix type ---")
	
	prefixExamples := make(map[byte]int)
	for _, occ := range occurrences {
		prefix := occ.before[15]
		if prefixExamples[prefix] >= 3 {
			continue
		}
		prefixExamples[prefix]++
		
		fmt.Printf("\nPrefix 0x%02X, occurrence at 0x%06X:\n", prefix, occ.offset)
		fmt.Printf("  Before: %s\n", hex.EncodeToString(occ.before[:]))
		fmt.Printf("  Marker: 607385fe\n")
		fmt.Printf("  After:  %s\n", hex.EncodeToString(occ.after[:]))
		
		// Try to find floats at various offsets after marker
		for off := 0; off <= 20; off += 4 {
			if off+12 <= 32 {
				x := readFloat(occ.after[off:])
				y := readFloat(occ.after[off+4:])
				z := readFloat(occ.after[off+8:])
				
				if isReasonable(x) && isReasonable(y) && isReasonable(z) {
					fmt.Printf("  @ offset +%d: (%.2f, %.2f, %.2f)\n", off+4, x, y, z)
				}
			}
		}
	}
	
	// Now search for the specific pattern that has valid positions
	fmt.Println("\n\n=== Searching for valid position packets ===")
	
	validPositions := 0
	type validPos struct {
		offset int
		prefix string
		x, y, z float32
	}
	var validPosns []validPos
	
	for _, occ := range occurrences {
		// Try different offset combinations to find where XYZ floats are
		// Pattern might be: [something] 607385fe [seq] [flags] [X] [Y] [Z]
		
		for off := 4; off <= 16; off += 4 {
			if off+12 > 32 {
				continue
			}
			
			x := readFloat(occ.after[off:])
			y := readFloat(occ.after[off+4:])
			z := readFloat(occ.after[off+8:])
			
			// Nighthaven-specific coordinate ranges (guess based on map)
			if x >= -100 && x <= 100 && y >= -100 && y <= 100 && z >= -10 && z <= 30 {
				// Additional filter: at least one non-tiny value
				absX := math.Abs(float64(x))
				absY := math.Abs(float64(y))
				if absX > 5 || absY > 5 {
					validPositions++
					if len(validPosns) < 30 {
						validPosns = append(validPosns, validPos{
							offset: occ.offset,
							prefix: hex.EncodeToString(occ.before[12:]),
							x: x, y: y, z: z,
						})
					}
				}
			}
		}
	}
	
	fmt.Printf("Found %d potential valid positions\n", validPositions)
	fmt.Println("\nFirst 30 valid positions:")
	for _, p := range validPosns {
		fmt.Printf("  @ 0x%06X [%s]: (%.2f, %.2f, %.2f)\n", p.offset, p.prefix, p.x, p.y, p.z)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isReasonable(f float32) bool {
	if f != f { // NaN
		return false
	}
	if math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -500 && f <= 500
}
