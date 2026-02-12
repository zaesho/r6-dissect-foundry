package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: findpos <dump.bin>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File size: %d bytes\n\n", len(data))

	// Try the pattern 62e45e that appeared before position coords
	marker := []byte{0x62, 0xe4, 0x5e}
	
	fmt.Println("=== Analyzing marker 62e45e ===")
	
	matches := findPattern(data, marker)
	fmt.Printf("Found %d matches\n\n", len(matches))
	
	// Show matches with extended context
	fmt.Println("Row | Offset     | Marker + 20 bytes after | Position (X, Y, Z)")
	fmt.Println("----+------------+-------------------------+--------------------")
	
	validCoords := 0
	for i, offset := range matches {
		if i >= 100 {
			break
		}
		
		if offset+23 >= len(data) {
			continue
		}
		
		after := data[offset : offset+23]
		
		// Try reading floats at different offsets
		for floatOff := 7; floatOff <= 10; floatOff++ {
			if offset+floatOff+12 > len(data) {
				continue
			}
			f1 := readFloat(data[offset+floatOff:])
			f2 := readFloat(data[offset+floatOff+4:])
			f3 := readFloat(data[offset+floatOff+8:])
			
			absX := math.Abs(float64(f1))
			absY := math.Abs(float64(f2))
			absZ := math.Abs(float64(f3))
			
			// Check for valid position coordinates
			if absX >= 1 && absX <= 100 && 
			   absY >= 1 && absY <= 100 && 
			   absZ >= 0 && absZ <= 20 &&
			   !math.IsNaN(float64(f1)) && !math.IsNaN(float64(f2)) && !math.IsNaN(float64(f3)) {
				validCoords++
				if validCoords <= 50 {
					fmt.Printf("%3d | 0x%08X | %s | off+%d: (%.2f, %.2f, %.2f)\n",
						i, offset, hex.EncodeToString(after), floatOff, f1, f2, f3)
				}
			}
		}
	}
	
	fmt.Printf("\nTotal valid coordinates found: %d / %d matches\n", validCoords, len(matches))
	
	// Now look for uint16 at offset 0x0A and 0x16 from this marker
	fmt.Println("\n=== Checking for incrementing sequence at offset +3 and +4 ===")
	
	prevVal := uint16(0)
	increments := 0
	
	for i, offset := range matches {
		if i >= 200 {
			break
		}
		if offset+5 >= len(data) {
			continue
		}
		
		val := binary.LittleEndian.Uint16(data[offset+3:])
		
		if i > 0 && val > prevVal && val-prevVal <= 10 {
			increments++
		}
		prevVal = val
	}
	
	fmt.Printf("Offset +3 (uint16): %d/%d incremented\n", increments, 199)
	
	// Try different approach - look for bytes that increment
	fmt.Println("\n=== Searching for incrementing bytes at each offset ===")
	
	for checkOff := 0; checkOff <= 20; checkOff++ {
		prevByte := uint8(0)
		incs := 0
		
		for i, offset := range matches {
			if i >= 200 {
				break
			}
			if offset+checkOff >= len(data) {
				continue
			}
			
			b := data[offset+checkOff]
			if i > 0 && b == prevByte+1 {
				incs++
			}
			prevByte = b
		}
		
		if incs > 20 {
			fmt.Printf("Offset +%d: %d/%d incremented by 1\n", checkOff, incs, 199)
		}
	}
	
	// Also try the pattern 0025 that appeared
	fmt.Println("\n=== Analyzing marker 0025 (00 25) ===")
	
	marker2 := []byte{0x00, 0x25}
	matches2 := findPattern(data, marker2)
	fmt.Printf("Found %d matches\n", len(matches2))
	
	// Show some samples with position data
	fmt.Println("\nSamples:")
	shown := 0
	for _, offset := range matches2 {
		if shown >= 30 {
			break
		}
		if offset+20 >= len(data) {
			continue
		}
		
		// Try reading floats at offset +10 from the marker
		for floatOff := 8; floatOff <= 12; floatOff++ {
			if offset+floatOff+12 > len(data) {
				continue
			}
			f1 := readFloat(data[offset+floatOff:])
			f2 := readFloat(data[offset+floatOff+4:])
			f3 := readFloat(data[offset+floatOff+8:])
			
			absX := math.Abs(float64(f1))
			absY := math.Abs(float64(f2))
			absZ := math.Abs(float64(f3))
			
			if absX >= 5 && absX <= 50 && 
			   absY >= 5 && absY <= 50 && 
			   absZ >= 0 && absZ <= 15 {
				shown++
				before := ""
				if offset >= 5 {
					before = hex.EncodeToString(data[offset-5 : offset])
				}
				fmt.Printf("0x%08X: before=%s marker=%s -> off+%d: (%.2f, %.2f, %.2f)\n",
					offset, before, hex.EncodeToString(data[offset:offset+10]), floatOff, f1, f2, f3)
			}
		}
	}
}

func findPattern(data, pattern []byte) []int {
	var matches []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j, b := range pattern {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			matches = append(matches, i)
		}
	}
	return matches
}

func readFloat(data []byte) float32 {
	if len(data) < 4 {
		return 0
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}
