package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/klauspost/compress/zstd"
)

// Search for patterns in the raw decompressed data that might contain player positions
// beyond the 60 73 85 fe marker

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

	// Read and decompress the entire file
	data, err := decompressReplay(f)
	if err != nil {
		fmt.Printf("Error decompressing: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decompressed size: %d bytes\n\n", len(data))

	// Search for the known marker
	knownMarker := []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	knownCount := countOccurrences(data, knownMarker)
	fmt.Printf("Known marker (00 00 60 73 85 fe): %d occurrences\n", knownCount)

	// Search for other potential markers
	// Look for patterns that repeat frequently and precede float-like data
	searchPatterns := [][]byte{
		{0x00, 0x00, 0x61, 0x73, 0x85, 0xfe},
		{0x00, 0x00, 0x62, 0x73, 0x85, 0xfe},
		{0x00, 0x00, 0x63, 0x73, 0x85, 0xfe},
		{0x00, 0x00, 0x64, 0x73, 0x85, 0xfe},
		{0x00, 0x00, 0x00, 0x73, 0x85, 0xfe},
		{0x73, 0x85, 0xfe},
		{0x85, 0xfe},
	}

	for _, pattern := range searchPatterns {
		count := countOccurrences(data, pattern)
		if count > 100 {
			fmt.Printf("Pattern %02X: %d occurrences\n", pattern, count)
		}
	}

	// Search for repeating byte patterns that could be packet headers
	fmt.Printf("\n=== Searching for 4-byte patterns that repeat 1000+ times ===\n")
	patternCounts := make(map[uint32]int)
	for i := 0; i < len(data)-4; i++ {
		pattern := binary.LittleEndian.Uint32(data[i : i+4])
		// Skip very common patterns like 00000000
		if pattern != 0 && pattern != 0xFFFFFFFF {
			patternCounts[pattern]++
		}
	}

	// Find patterns that appear frequently
	type patternCount struct {
		pattern uint32
		count   int
	}
	var frequent []patternCount
	for p, c := range patternCounts {
		if c > 5000 {
			frequent = append(frequent, patternCount{p, c})
		}
	}

	fmt.Printf("Found %d patterns appearing 5000+ times\n", len(frequent))
	for i, pc := range frequent {
		if i >= 20 {
			break
		}
		fmt.Printf("  %08X: %d times\n", pc.pattern, pc.count)
	}

	// Look for coordinate-like floats and see what precedes them
	fmt.Printf("\n=== Analyzing what precedes valid coordinate triplets ===\n")
	precedingPatterns := make(map[string]int)
	
	for i := 16; i < len(data)-12; i++ {
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[i : i+4]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[i+8 : i+12]))

		if isValidCoord(x) && isValidCoord(y) && isValidZ(z) {
			// Look at 8 bytes before this position
			preceding := fmt.Sprintf("%02X", data[i-8:i])
			precedingPatterns[preceding]++
		}
	}

	// Show most common preceding patterns
	type pp struct {
		pattern string
		count   int
	}
	var precedingList []pp
	for p, c := range precedingPatterns {
		precedingList = append(precedingList, pp{p, c})
	}

	fmt.Printf("Most common 8-byte patterns before valid coordinates:\n")
	for i, patt := range precedingList {
		if patt.count > 100 {
			fmt.Printf("  %s: %d times\n", patt.pattern, patt.count)
		}
		if i >= 50 {
			break
		}
	}
}

func decompressReplay(f *os.File) ([]byte, error) {
	// Read file header to skip it
	header := make([]byte, 7)
	f.Read(header)
	
	// Read magic and version
	magic := string(header)
	if magic != "dissect" {
		return nil, fmt.Errorf("not a dissect file")
	}

	// Seek past header - try reading rest of file as zstd
	f.Seek(0, 0)
	allData, _ := io.ReadAll(f)
	
	// Find where compressed data starts (after header)
	// Look for zstd magic (28 B5 2F FD)
	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	idx := bytes.Index(allData, zstdMagic)
	if idx < 0 {
		return nil, fmt.Errorf("no zstd data found")
	}

	fmt.Printf("Found zstd data at offset %d\n", idx)

	// Decompress from that point
	decoder, err := zstd.NewReader(bytes.NewReader(allData[idx:]))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	return io.ReadAll(decoder)
}

func countOccurrences(data []byte, pattern []byte) int {
	count := 0
	for i := 0; i <= len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			count++
		}
	}
	return count
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100 && f != 0
}

func isValidZ(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -10 && f <= 50
}
