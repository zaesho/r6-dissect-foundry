package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

// Custom reader to access raw bytes
type rawReader struct {
	*dissect.Reader
	rawBytes []byte
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: findmarkers <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Create reader but access internal bytes
	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Read without callbacks to get raw buffer
	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Map: %s\n", r.Header.Map.String())
	fmt.Printf("Players: %d\n\n", len(r.Header.Players))

	// We can't access raw bytes directly, so let's look at what markers we know about
	// The 62 e4 5e marker worked for Chalet, let's search in the decompressed data
	
	// For now, report what we found
	movements := r.GetMovementData()
	if movements == nil || len(movements) == 0 {
		fmt.Println("No movement data found with current marker (62 e4 5e)")
		fmt.Println("\nThis map may use a different marker for position data.")
		fmt.Println("Further analysis needed to identify map-specific markers.")
	} else {
		fmt.Printf("Found %d movement entries\n", len(movements))
		for _, m := range movements {
			fmt.Printf("  %s: %d positions\n", m.Username, len(m.Positions))
		}
	}
}

func readFloat(data []byte) float32 {
	if len(data) < 4 {
		return 0
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
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

func isValidCoord(f float32) bool {
	if f != f { // NaN check
		return false
	}
	return f >= -200 && f <= 200
}

// Analyze raw bytes to find potential position markers
func analyzeForPositionMarkers(data []byte) {
	fmt.Println("\n=== Searching for position-like data patterns ===")
	
	// Look for float triplets that could be positions
	markerCounts := make(map[string]int)
	markerExamples := make(map[string][]string)
	
	for i := 10; i < len(data)-12; i++ {
		x := readFloat(data[i:])
		y := readFloat(data[i+4:])
		z := readFloat(data[i+8:])
		
		// Check if this looks like valid position coordinates
		absX := math.Abs(float64(x))
		absY := math.Abs(float64(y))
		absZ := math.Abs(float64(z))
		
		if absX >= 5 && absX <= 100 &&
		   absY >= 5 && absY <= 100 &&
		   absZ >= 0 && absZ <= 20 &&
		   isValidCoord(x) && isValidCoord(y) && isValidCoord(z) {
			// Get the 3-byte marker before this position
			marker := hex.EncodeToString(data[i-3 : i])
			markerCounts[marker]++
			
			if len(markerExamples[marker]) < 3 {
				example := fmt.Sprintf("(%.2f, %.2f, %.2f)", x, y, z)
				markerExamples[marker] = append(markerExamples[marker], example)
			}
		}
	}
	
	// Report top markers
	fmt.Printf("Found %d unique 3-byte markers before valid position data\n", len(markerCounts))
	
	// Find markers with highest counts
	type markerInfo struct {
		marker string
		count  int
	}
	var topMarkers []markerInfo
	for m, c := range markerCounts {
		if c >= 20 {
			topMarkers = append(topMarkers, markerInfo{m, c})
		}
	}
	
	fmt.Printf("\nTop markers (20+ occurrences):\n")
	for _, m := range topMarkers {
		fmt.Printf("  %s: %d times\n", m.marker, m.count)
		for _, ex := range markerExamples[m.marker] {
			fmt.Printf("    Example: %s\n", ex)
		}
	}
}
