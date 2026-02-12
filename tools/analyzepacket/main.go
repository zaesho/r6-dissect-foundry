package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	// Analyze the Border dump which has clear position patterns
	data, err := os.ReadFile("samplefiles/border_R01_dump.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Analyzing Border dump for position packet structure ===\n")

	// Look for one of the Border position markers
	marker := []byte{0x00, 0x2c, 0x36, 0x14, 0x9b} // 002c36149b
	
	fmt.Printf("Searching for marker %s...\n", hex.EncodeToString(marker))
	
	var offsets []int
	for i := 0; i <= len(data)-len(marker); i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			offsets = append(offsets, i)
		}
	}

	fmt.Printf("Found %d occurrences\n\n", len(offsets))

	// Print structure around first 10 occurrences
	fmt.Println("Structure analysis (showing 32 bytes before and 20 bytes after marker):")
	fmt.Println("Looking for patterns in the bytes preceding the position data...\n")

	limit := 10
	if len(offsets) < limit {
		limit = len(offsets)
	}

	for i := 0; i < limit; i++ {
		off := offsets[i]
		
		// Read position (5 bytes after marker start, so position is at marker + 5)
		posOff := off + 5
		if posOff+12 > len(data) {
			continue
		}
		
		x := readFloat(data[posOff:])
		y := readFloat(data[posOff+4:])
		z := readFloat(data[posOff+8:])
		
		fmt.Printf("=== Occurrence %d at offset 0x%X ===\n", i+1, off)
		fmt.Printf("Position: (%.2f, %.2f, %.2f)\n", x, y, z)
		
		// Show context before marker
		startCtx := off - 32
		if startCtx < 0 {
			startCtx = 0
		}
		
		fmt.Printf("Before marker (-32 to 0):\n")
		printHexContext(data[startCtx:off], off-startCtx)
		
		fmt.Printf("Marker + Position (0 to +17):\n")
		endCtx := off + 17
		if endCtx > len(data) {
			endCtx = len(data)
		}
		printHexContext(data[off:endCtx], 0)
		
		fmt.Println()
	}

	// Now look at the spacing between occurrences
	fmt.Println("\n=== Spacing analysis ===")
	if len(offsets) > 1 {
		for i := 1; i < min(20, len(offsets)); i++ {
			diff := offsets[i] - offsets[i-1]
			fmt.Printf("Offset[%d] - Offset[%d] = %d bytes\n", i, i-1, diff)
		}
	}

	// Compare multiple markers to see if they're interleaved (different players)
	fmt.Println("\n\n=== Comparing multiple markers (potential different players) ===")
	
	markers := [][]byte{
		{0x00, 0x2c, 0x36, 0x14, 0x9b},
		{0x00, 0x70, 0x88, 0x98, 0x58},
		{0x00, 0xcb, 0x0f, 0xbe, 0x42},
		{0x00, 0xe1, 0x94, 0x50, 0xb9},
	}
	
	type occurrence struct {
		marker int
		offset int
		x, y, z float32
	}
	
	var allOccs []occurrence
	
	for mi, m := range markers {
		for i := 0; i <= len(data)-5; i++ {
			match := true
			for j, b := range m {
				if data[i+j] != b {
					match = false
					break
				}
			}
			if match {
				posOff := i + 5
				if posOff+12 <= len(data) {
					allOccs = append(allOccs, occurrence{
						marker: mi,
						offset: i,
						x: readFloat(data[posOff:]),
						y: readFloat(data[posOff+4:]),
						z: readFloat(data[posOff+8:]),
					})
				}
			}
		}
	}
	
	// Sort by offset
	for i := 0; i < len(allOccs)-1; i++ {
		for j := i + 1; j < len(allOccs); j++ {
			if allOccs[j].offset < allOccs[i].offset {
				allOccs[i], allOccs[j] = allOccs[j], allOccs[i]
			}
		}
	}
	
	fmt.Println("\nFirst 30 position updates (sorted by offset), showing marker ID:")
	for i := 0; i < min(30, len(allOccs)); i++ {
		o := allOccs[i]
		fmt.Printf("Marker %d @ 0x%06X: (%.2f, %.2f, %.2f)\n", o.marker, o.offset, o.x, o.y, o.z)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func printHexContext(data []byte, offset int) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		
		fmt.Printf("  +%02d: ", i-offset)
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
		}
		fmt.Println()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
