package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
)

func main() {
	files := []string{
		"samplefiles/R01_dump.bin",           // Chalet
		"samplefiles/nighthaven_R01_dump.bin", // Nighthaven Labs
		"samplefiles/border_R01_dump.bin",     // Border
	}

	mapNames := []string{"Chalet", "Nighthaven", "Border"}

	// Load all files
	var datas [][]byte
	for i, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", f, err)
			os.Exit(1)
		}
		fmt.Printf("%s: %d bytes\n", mapNames[i], len(data))
		datas = append(datas, data)
	}

	fmt.Println("\n=== Looking for float triplets that could be positions ===")
	fmt.Println("Searching for patterns with coords in range [-100, 100] for X/Y and [-10, 30] for Z...\n")

	// For each file, find 5-byte markers that precede valid position-like float triplets
	for i, data := range datas {
		fmt.Printf("\n--- %s ---\n", mapNames[i])
		findPositionMarkers(data, mapNames[i])
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isValidCoord(f float32, minVal, maxVal float32) bool {
	if f != f { // NaN
		return false
	}
	if math.IsInf(float64(f), 0) {
		return false
	}
	return f >= minVal && f <= maxVal
}

func findPositionMarkers(data []byte, mapName string) {
	// Count occurrences of each 5-byte pattern before valid position triplets
	type markerStats struct {
		count    int
		examples []string
		offsets  []int
	}
	markers := make(map[string]*markerStats)

	for i := 5; i < len(data)-12; i++ {
		x := readFloat(data[i:])
		y := readFloat(data[i+4:])
		z := readFloat(data[i+8:])

		// Check for valid position coordinates
		// X, Y: typically -100 to 100 for R6 maps
		// Z: typically -5 to 30 (floor levels)
		if isValidCoord(x, -100, 100) && isValidCoord(y, -100, 100) && isValidCoord(z, -10, 30) {
			// Additional filtering: at least one coord should be "significant" (not near zero)
			absX := math.Abs(float64(x))
			absY := math.Abs(float64(y))
			
			if absX < 1 && absY < 1 {
				continue // Both X and Y near zero, probably not a real position
			}

			marker := hex.EncodeToString(data[i-5 : i])
			
			if markers[marker] == nil {
				markers[marker] = &markerStats{}
			}
			
			markers[marker].count++
			markers[marker].offsets = append(markers[marker].offsets, i)
			
			if len(markers[marker].examples) < 3 {
				ex := fmt.Sprintf("(%.2f, %.2f, %.2f)", x, y, z)
				markers[marker].examples = append(markers[marker].examples, ex)
			}
		}
	}

	// Sort by count
	type kv struct {
		marker string
		stats  *markerStats
	}
	var sorted []kv
	for m, s := range markers {
		if s.count >= 50 { // Only show markers with 50+ occurrences
			sorted = append(sorted, kv{m, s})
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].stats.count > sorted[j].stats.count
	})

	fmt.Printf("Found %d markers with 50+ position-like triplets\n", len(sorted))
	
	// Show top 20
	limit := 20
	if len(sorted) < limit {
		limit = len(sorted)
	}
	
	for i := 0; i < limit; i++ {
		m := sorted[i]
		fmt.Printf("\n  Marker %s: %d occurrences\n", m.marker, m.stats.count)
		for _, ex := range m.stats.examples {
			fmt.Printf("    Example: %s\n", ex)
		}
		
		// Check if offsets are evenly spaced (would indicate regular updates)
		if len(m.stats.offsets) > 10 {
			var diffs []int
			for j := 1; j < min(100, len(m.stats.offsets)); j++ {
				diffs = append(diffs, m.stats.offsets[j]-m.stats.offsets[j-1])
			}
			// Calculate average diff
			sum := 0
			for _, d := range diffs {
				sum += d
			}
			avgDiff := sum / len(diffs)
			fmt.Printf("    Avg spacing: %d bytes between occurrences\n", avgDiff)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
